package flowexport

import "fmt"

func (e *Engine) decodeV5(data []byte, state *domainState, batch *Batch, env Envelope, domain, seq, uptime uint32, exportNs int64) (int, error) {
	count := int(u16(data[2:]))
	if count > 30 || len(data) != 24+48*count {
		return 0, fmt.Errorf("invalid NetFlow v5 count/record length")
	}
	sample := u16(data[22:])
	state.sampling = Sampling{Status: "none", Interval: 1, Scope: "datagram"}
	if sample&0x3fff != 0 {
		state.sampling = Sampling{Status: "declared-as-reported", Interval: uint64(sample & 0x3fff), Algorithm: uint64(sample >> 14), Scope: "datagram"}
	}
	for i := 0; i < count; i++ {
		r := data[24+48*i : 24+48*(i+1)]
		fields := []Field{
			{ID: 8, Value: r[:4]}, {ID: 12, Value: r[4:8]}, {ID: 15, Value: r[8:12]},
			{ID: 10, Value: r[12:14]}, {ID: 14, Value: r[14:16]}, {ID: 2, Value: r[16:20]}, {ID: 1, Value: r[20:24]},
			{ID: 22, Value: r[24:28]}, {ID: 21, Value: r[28:32]}, {ID: 7, Value: r[32:34]}, {ID: 11, Value: r[34:36]},
			{ID: 6, Value: r[37:38]}, {ID: 4, Value: r[38:39]}, {ID: 5, Value: r[39:40]},
			{ID: 16, Value: r[40:42]}, {ID: 17, Value: r[42:44]}, {ID: 9, Value: r[44:45]}, {ID: 13, Value: r[45:46]},
		}
		obs, err := normalize(fields, 5, state, env, domain, seq, 0, i, uptime, exportNs)
		if err != nil {
			return 0, err
		}
		batch.Observations = append(batch.Observations, obs)
	}
	return count, nil
}

func (e *Engine) decodeSets(data []byte, version uint16, state *domainState, batch *Batch, env Envelope, domain, seq, uptime uint32, exportNs, watermark int64) (int, error) {
	count := 0
	for len(data) > 0 {
		if len(data) < 4 {
			return count, fmt.Errorf("truncated flow set header")
		}
		id, length := u16(data), int(u16(data[2:]))
		if length < 4 || length > len(data) {
			return count, fmt.Errorf("invalid flow set length %d", length)
		}
		body := data[4:length]
		data = data[length:]
		switch {
		case (version == 9 && (id == 0 || id == 1)) || (version == 10 && (id == 2 || id == 3)):
			options := (version == 9 && id == 1) || (version == 10 && id == 3)
			if err := e.templates(body, version, options, state, watermark); err != nil {
				return count, err
			}
		case id >= 256:
			t, ok := state.templates[id]
			if !ok {
				e.health.MissingTemplates++
				batch.Issues = append(batch.Issues, Issue{Code: "missing-template", TemplateID: id, Envelope: env, Detail: "data retained in source datagram; no decoded record inferred"})
				continue
			}
			records, err := e.records(body, t)
			if err != nil {
				return count, fmt.Errorf("template %d: %w", id, err)
			}
			for _, fields := range records {
				count++
				if t.options {
					if !applyOptions(fields, version, state, domain) {
						batch.Issues = append(batch.Issues, Issue{Code: "unsupported-options-scope", TemplateID: id, Envelope: env, Detail: "sampling/timeout options preserved but not applied beyond their declared scope"})
					}
					continue
				}
				obs, err := normalize(fields, version, state, env, domain, seq, id, len(batch.Observations), uptime, exportNs)
				if err != nil {
					return count, err
				}
				batch.Observations = append(batch.Observations, obs)
			}
		default:
			return count, fmt.Errorf("unsupported reserved flow set %d", id)
		}
	}
	return count, nil
}

func (e *Engine) templates(data []byte, version uint16, options bool, state *domainState, seen int64) error {
	for len(data) > 0 {
		if len(data) <= 3 && zero(data) {
			return nil
		}
		if len(data) < 4 {
			return fmt.Errorf("truncated template header")
		}
		id, count := u16(data), int(u16(data[2:]))
		data = data[4:]
		if version == 10 && count == 0 {
			if id == 2 || id == 3 {
				for key, t := range state.templates {
					if t.options == options {
						delete(state.templates, key)
					}
				}
			} else if id >= 256 {
				delete(state.templates, id)
			} else {
				return fmt.Errorf("invalid template withdrawal %d", id)
			}
			continue
		}
		scopes := 0
		if options {
			if len(data) < 2 {
				return fmt.Errorf("truncated options template header")
			}
			if version == 9 {
				if count%4 != 0 || int(u16(data))%4 != 0 {
					return fmt.Errorf("invalid NetFlow v9 option/scope length")
				}
				scopes = count / 4
				count = scopes + int(u16(data))/4
			} else {
				scopes = int(u16(data))
			}
			data = data[2:]
		}
		if id < 256 || count < 1 || count > e.config.MaxFields || scopes > count || (options && scopes < 1) {
			return fmt.Errorf("invalid template id/field/scope count: %d/%d/%d", id, count, scopes)
		}
		fields := make([]fieldSpec, 0, count)
		for i := 0; i < count; i++ {
			if len(data) < 4 {
				return fmt.Errorf("truncated template field")
			}
			f := fieldSpec{id: u16(data), length: u16(data[2:]), scope: i < scopes}
			data = data[4:]
			if version == 10 && f.id&0x8000 != 0 {
				if len(data) < 4 {
					return fmt.Errorf("truncated enterprise field")
				}
				f.id &= 0x7fff
				f.enterprise = u32(data)
				f.enterpriseProvided = true
				data = data[4:]
			}
			if f.length == 0 || (version == 9 && f.length == 65535) {
				return fmt.Errorf("invalid template field length")
			}
			fields = append(fields, f)
		}
		state.templates[id] = template{fields: fields, options: options, seen: seen}
	}
	return nil
}

func (e *Engine) records(data []byte, t template) ([][]Field, error) {
	minimum := 0
	for _, f := range t.fields {
		if f.length == 65535 {
			minimum++
		} else {
			minimum += int(f.length)
		}
	}
	if minimum == 0 {
		return nil, fmt.Errorf("zero-size record")
	}
	var records [][]Field
	for len(data) > 0 {
		if len(data) < minimum {
			if len(data) <= 3 && zero(data) {
				break
			}
			return nil, fmt.Errorf("truncated data record")
		}
		if minimum <= 3 && len(data) <= 3 && zero(data) {
			return nil, fmt.Errorf("ambiguous short-record padding")
		}
		fields := make([]Field, 0, len(t.fields))
		for _, spec := range t.fields {
			length := int(spec.length)
			if spec.length == 65535 {
				if len(data) < 1 {
					return nil, fmt.Errorf("truncated variable-length prefix")
				}
				length = int(data[0])
				data = data[1:]
				if length == 255 {
					if len(data) < 2 {
						return nil, fmt.Errorf("truncated extended length")
					}
					length = int(u16(data))
					data = data[2:]
				}
			}
			if length > len(data) {
				return nil, fmt.Errorf("truncated field body")
			}
			fields = append(fields, Field{ID: spec.id, Enterprise: spec.enterprise, EnterpriseProvided: spec.enterpriseProvided, Scope: spec.scope, Value: append([]byte(nil), data[:length]...)})
			data = data[length:]
		}
		records = append(records, fields)
	}
	return records, nil
}

func applyOptions(fields []Field, version uint16, state *domainState, domain uint32) bool {
	for _, f := range fields {
		if !f.Scope {
			continue
		}
		n, err := number(f.Value)
		if err != nil || f.EnterpriseProvided || (version == 9 && f.ID != 1) || (version == 10 && (f.ID != 149 || n != uint64(domain))) {
			return false
		}
	}
	for _, f := range fields {
		if f.Scope || f.EnterpriseProvided {
			continue
		}
		n, err := number(f.Value)
		if err != nil {
			continue
		}
		switch f.ID {
		case 34, 50:
			state.sampling.Interval = n
			state.sampling.Status = "declared-as-reported"
			state.sampling.Scope = "exporter-domain"
		case 35, 49:
			state.sampling.Algorithm = n
		case 36:
			state.active = ptr(n)
		case 37:
			state.idle = ptr(n)
		}
	}
	return true
}
