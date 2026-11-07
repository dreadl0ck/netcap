'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let token = '', epoch = 0, fleetEpoch = 0, kind = '', active = '', pending = '', stagedSource = '', formSource = '', model = null;
  const policy = '/api/v1/policy/';
  const busy = new Set();
  const print = (id, data) => { $(id).textContent = JSON.stringify(data, null, 2); };
  function notice(text, error = false) { $('notice').textContent = text; $('notice').classList.toggle('error', error); }
  async function api(path, body, method = body === undefined ? 'GET' : 'POST') {
    if (!token) throw new Error('Connect with a bearer token first.');
    const session = epoch;
    const response = await fetch(path, {
      method, credentials: 'omit', cache: 'no-store', redirect: 'error',
      headers: { Authorization: 'Bearer ' + token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (session !== epoch) throw new Error('Session ended; response discarded.');
    const text = await response.text();
    if (session !== epoch) throw new Error('Session ended; response discarded.');
    let data;
    try { data = text ? JSON.parse(text) : null; } catch { throw new Error(`HTTP ${response.status}: invalid API response`); }
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${data?.error || text}`);
    return data;
  }
  function action(id, fn) {
    $(id).addEventListener('click', async event => {
      event.preventDefault();
      const button = event.currentTarget, session = epoch;
      busy.add(id);
      button.disabled = true;
      notice('Working…');
      try { const result = await fn(); if (session === epoch) notice(result === false ? 'Operation cancelled.' : 'Operation completed.'); }
      catch (err) { if (session === epoch) notice(err.message, true); }
      finally {
        busy.delete(id); button.disabled = false; syncActivation();
        if (session === epoch && (document.activeElement === document.body || $('confirm').contains(document.activeElement))) button.focus();
      }
    });
  }
  function syncActivation() { $('activate').disabled = busy.has('activate') || !token || !pending || stagedSource !== $('bundle').value; }
  function invalidate() { pending = ''; stagedSource = ''; $('pending').textContent = 'Source changed; check and stage again'; syncActivation(); }
  function key() { return crypto.randomUUID(); }
  function confirm(message) {
    const dialog = $('confirm'), previous = document.activeElement;
    $('confirm-text').textContent = message;
    dialog.returnValue = 'cancel'; dialog.showModal();
    return new Promise(resolve => dialog.addEventListener('close', () => {
      previous?.focus(); resolve(dialog.returnValue === 'confirm');
    }, { once: true }));
  }
  function logout() {
    epoch++; fleetEpoch++; token = ''; active = ''; pending = ''; stagedSource = ''; formSource = ''; model = null;
    if ($('confirm').open) $('confirm').close('cancel');
    document.querySelectorAll('textarea,input').forEach(el => { el.value = ''; });
    ['capabilities', 'result', 'audit-result', 'fleet-result', 'lease-result', 'targets', 'jobs', 'lease-list', 'rules'].forEach(id => $(id).replaceChildren());
    $('active').textContent = 'Unknown'; $('pending').textContent = 'None staged in this tab'; $('service-label').textContent = '';
    $('workspace').hidden = true; $('login').hidden = false; $('logout').hidden = true;
    $('native-fields').disabled = true; $('revision').replaceChildren();
    notice('Logged out. Token and workspace cleared.'); $('token').focus(); syncActivation();
  }
  $('logout').addEventListener('click', logout);
  window.addEventListener('pagehide', logout);
  $('bundle').addEventListener('input', invalidate);
  async function refreshPolicy(load = false) {
    const current = await api(policy + 'revision');
    const revisions = await api(policy + 'revisions');
    active = current.revision; $('active').textContent = active; $('expected').value = active;
    const selected = $('revision').value;
    $('revision').replaceChildren(...revisions.map(rev => {
      const option = document.createElement('option'); option.value = rev;
      option.textContent = (rev === active ? 'Active · ' : 'Retained · ') + rev;
      return option;
    }));
    if (revisions.includes(selected)) $('revision').value = selected;
    if (load) { $('bundle').value = JSON.stringify(current.bundle, null, 2); invalidate(); $('pending').textContent = 'None staged in this tab'; }
  }
  async function refresh() {
    if (kind === 'policy') { print('capabilities', await api(policy + 'capabilities')); await refreshPolicy(); }
    if (kind === 'fleet') await loadFleet();
    if (kind === 'leases') await listLeases();
  }
  $('login').addEventListener('submit', async event => {
    event.preventDefault(); const button = event.submitter; button.disabled = true;
    token = $('token').value; $('token').value = ''; epoch++;
    try {
      kind = await (await fetch('/console/service', { credentials: 'omit', redirect: 'error' })).text();
      if (!['policy', 'fleet', 'leases'].includes(kind)) throw new Error('Unsupported console listener.');
      // Fleet scope is explicit, so authentication is first checked by Load scoped fleet.
      if (kind === 'policy') { print('capabilities', await api(policy + 'capabilities')); await refreshPolicy(true); }
      if (kind === 'leases') await listLeases();
      $('login').hidden = true; $('workspace').hidden = false; $('logout').hidden = false;
      for (const id of ['policy', 'fleet', 'leases']) $(id).hidden = id !== kind;
      document.querySelectorAll('nav a').forEach(link => { link.hidden = link.hash !== '#runtime' && link.hash !== '#' + kind; });
      $('service-label').textContent = `Administrative listener: ${location.origin} · ${kind}. Permissions are enforced by the server.`;
      notice(kind === 'fleet' ? 'Token held in memory. Enter tenant and application to authenticate and load scope.' : 'Connected.');
      $('refresh').focus();
    } catch (err) { token = ''; notice(err.message, true); }
    finally { button.disabled = false; syncActivation(); }
  });
  action('refresh', refresh);
  action('check', async () => print('result', await api(policy + 'check', { bundle: $('bundle').value })));
  action('stage', async () => {
    const source = $('bundle').value;
    const out = await api(policy + 'stage', { bundle: source, idempotency_key: key() });
    await refreshPolicy();
    if (source !== $('bundle').value) { invalidate(); throw new Error('Source changed during staging; stage the current source.'); }
    pending = out.revision; stagedSource = source; $('pending').textContent = pending;
    $('revision').value = pending; print('result', out); syncActivation();
  });
  action('diff', async () => print('result', await api(policy + 'diff', { revision: active, other_revision: $('revision').value })));
  action('inspect', async () => {
    if (!await confirm('Replace the current editor source with this retained revision? Download unsaved source first.')) return false;
    const out = await api(policy + 'revision?revision=' + encodeURIComponent($('revision').value));
    $('bundle').value = JSON.stringify(out.bundle, null, 2); invalidate();
  });
  async function deploy(op, revision) {
    const expected = $('expected').value, session = epoch;
    if (!revision) throw new Error('Select or stage a revision first.');
    if (!await confirm(`${op === 'activate' ? 'Activate' : 'Roll back to'} ${revision}? Expected active: ${expected}. This changes live traffic policy.`) || session !== epoch) return false;
    const out = await api(policy + op, { revision, expected_revision: expected, idempotency_key: key() });
    print('result', out); pending = ''; stagedSource = ''; $('pending').textContent = 'None staged in this tab'; await refreshPolicy();
  }
  action('activate', () => deploy('activate', pending));
  action('rollback', () => deploy('rollback', $('revision').value));
  action('replay', async () => {
    const value = JSON.parse($('events').value);
    print('result', await api(policy + 'evaluate', { revision: $('revision').value, [Array.isArray(value) ? 'events' : 'event']: value }));
  });
  action('audit', async () => print('audit-result', await api(policy + 'audit?limit=100')));
  action('download', async () => {
    const blob = new Blob([$('bundle').value], { type: 'text/plain' }), url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'policy.txt'; a.click(); URL.revokeObjectURL(url);
  });

  function field(label, value, options, type = 'text') {
    const wrapper = document.createElement('label'); wrapper.textContent = label;
    const control = document.createElement(options ? 'select' : 'input');
    if (options) options.forEach(value => { const option = document.createElement('option'); option.textContent = value; control.append(option); });
    else control.type = type;
    control.value = value ?? ''; wrapper.append(control); return { wrapper, control };
  }
  function renderRules() {
    $('rules').replaceChildren();
    model.rules.forEach((rule, index) => {
      const box = document.createElement('fieldset'), legend = document.createElement('legend'); legend.textContent = `Rule ${index + 1}`; box.append(legend);
      const fields = document.createElement('div'); fields.className = 'fields'; box.append(fields);
      for (const [name, options, type] of [['id'], ['phase', ['request', 'response']], ['expression'], ['action', ['allow', 'deny']], ['status', null, 'number'], ['priority', null, 'number'], ['enabled', ['true', 'false']]]) {
        const value = name === 'enabled' ? String(rule.enabled !== false) : rule[name];
        const { wrapper, control } = field(`${name} · rule ${index + 1}`, value, options, type);
        control.addEventListener('input', () => { rule[name] = name === 'enabled' ? control.value === 'true' : type === 'number' ? Number(control.value) : control.value; });
        fields.append(wrapper);
      }
      const hint = document.createElement('p'); hint.textContent = 'Advanced native fields are retained; edit threshold, sequence and effects in source.'; box.append(hint);
      const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = `Remove rule ${index + 1}`;
      remove.addEventListener('click', () => { model.rules.splice(index, 1); renderRules(); $('add-rule').focus(); }); box.append(remove); $('rules').append(box);
    });
  }
  action('load-form', async () => {
    await api(policy + 'check', { bundle: $('bundle').value });
    const parsed = JSON.parse($('bundle').value);
    if (!parsed || !Array.isArray(parsed.rules)) throw new Error('JSON bundle must contain a rules array. YAML can be checked and staged directly from source.');
    model = parsed; formSource = $('bundle').value;
    for (const name of ['id', 'version', 'mode', 'default']) $('native-form').elements.namedItem(name).value = model[name] ?? '';
    $('native-fields').disabled = false; renderRules();
  });
  $('add-rule').addEventListener('click', () => { model.rules.push({ id: 'rule-' + (model.rules.length + 1), phase: 'request', expression: 'Path == "/blocked"', action: 'deny', status: 403, priority: 0 }); renderRules(); });
  $('native-form').addEventListener('submit', event => {
    event.preventDefault();
    if (formSource !== $('bundle').value) { notice('Source changed after loading the form. Reload the form to avoid overwriting edits.', true); return; }
    for (const name of ['id', 'version', 'mode', 'default']) model[name] = $('native-form').elements.namedItem(name).value;
    $('bundle').value = JSON.stringify(model, null, 2); formSource = $('bundle').value; invalidate(); notice('Form applied. Check and stage the edited source.');
  });

  function scope() {
    const tenant = $('tenant').value.trim(), app = $('app').value.trim();
    if (!tenant || !app) throw new Error('Tenant and application are required.');
    return { tenant, app };
  }
  function card(parent, className, title, text) {
    const el = document.createElement('div'); el.className = className;
    const h = document.createElement('h3'); h.textContent = title;
    const p = document.createElement('p'); p.textContent = text; el.append(h, p); $(parent).append(el); return el;
  }
  function operationButton(parent, label, fn) {
    const button = document.createElement('button'); button.textContent = label;
    button.addEventListener('click', async () => {
      const session = epoch; button.disabled = true; notice('Working…');
      try { const result = await fn(); if (session === epoch) notice(result === false ? 'Operation cancelled.' : 'Operation completed.'); }
      catch (err) { if (session === epoch) notice(err.message, true); }
      finally {
        button.disabled = false;
        if (session === epoch && (document.activeElement === document.body || $('confirm').contains(document.activeElement))) (button.isConnected ? button : $('refresh')).focus();
      }
    }); parent.append(button);
  }
  async function fleetOp(op, body) { const out = await api('/api/v1/fleet/' + op, { ...body, scope: scope() }); print('fleet-result', out); await loadFleet(); return out; }
  async function loadFleet() {
    const requestedScope = scope(), generation = ++fleetEpoch;
    const url = op => '/api/v1/fleet/' + op + '?' + new URLSearchParams(requestedScope);
    $('targets').replaceChildren(); $('jobs').replaceChildren(); $('capabilities').replaceChildren();
    const capabilities = await api(url('capabilities'));
    const status = await api(url('status'));
    if (generation !== fleetEpoch) return;
    print('capabilities', capabilities);
    for (const target of Object.values(status.targets || {})) {
      const row = card('targets', 'target', target.id, `Desired ${target.desired_revision || 'none'} / generation ${target.generation}; Observed ${target.observed_revision || 'none'} / generation ${target.observed_generation}. Desired drain: ${!!target.draining}; observed drain: ${!!target.observed_draining}. Desired revoke: ${!!target.revoked}; observed revoke: ${!!target.observed_revoked}. Last seen: ${target.last_seen}. ${target.error || ''}`);
      const actions = document.createElement('div'); actions.className = 'actions'; row.append(actions);
      for (const op of ['drain', 'revoke', 'resume']) operationButton(actions, `${op} ${target.id}`, async () => {
        const session = epoch;
        if (!await confirm(`${op} ${target.id} at generation ${target.generation} in ${requestedScope.tenant}/${requestedScope.app}?`) || session !== epoch) return false;
        if (JSON.stringify(scope()) !== JSON.stringify(requestedScope)) throw new Error('Scope changed; reload fleet first.');
        await fleetOp(op, { targets: [target.id], expected: { [target.id]: target.generation } });
      });
    }
    if (!Object.keys(status.targets || {}).length) card('targets', 'target', 'No targets', 'No enrolled targets in this scope.');
    for (const job of status.jobs || []) {
      const row = card('jobs', 'job', `${job.id} · ${job.phase}`, `Revision ${job.revision}. Deadline ${job.deadline}. ${job.failure || ''}`);
      for (const op of ['activate', 'promote', 'rollback']) operationButton(row, `${op} ${job.id}`, async () => {
        const session = epoch;
        if (!await confirm(`${op} rollout ${job.id} with expected phase ${job.phase}?`) || session !== epoch) return false;
        if (JSON.stringify(scope()) !== JSON.stringify(requestedScope)) throw new Error('Scope changed; reload fleet first.');
        await fleetOp(op, { id: job.id, expected_phase: job.phase });
      });
    }
  }
  for (const id of ['tenant', 'app']) $(id).addEventListener('input', () => {
    fleetEpoch++; ['targets', 'jobs', 'capabilities', 'fleet-result'].forEach(id => $(id).replaceChildren());
  });
  $('scope-form').addEventListener('submit', async event => { event.preventDefault(); try { await loadFleet(); notice('Scoped fleet loaded.'); } catch (err) { notice(err.message, true); } });
  action('fleet-stage', async () => print('fleet-result', await api('/api/v1/fleet/stage', { scope: scope(), bundle: $('fleet-bundle').value })));
  action('fleet-rollout', async () => {
    const body = JSON.parse($('rollout').value), session = epoch;
    if (!await confirm('Create this fleet rollout? Review targets, expected generations and deadline.') || session !== epoch) return false;
    await fleetOp('rollout', body);
  });
  async function listLeases() {
    const capabilities = await api('/api/v1/console/enforcer-capabilities');
    if (capabilities.error || capabilities.result?.isError) throw new Error('Enforcer capabilities unavailable.');
    print('capabilities', capabilities.result?.structuredContent || capabilities.result?.content);
    const leases = await api('/v1/leases');
    $('lease-list').replaceChildren();
    for (const lease of leases || []) {
      const row = card('lease-list', 'lease', lease.id, `${lease.source} · expires ${lease.expires_at} · scope ${JSON.stringify(lease.scope)}`);
      operationButton(row, `Revoke lease ${lease.id}`, async () => {
        const session = epoch;
        if (!await confirm(`Revoke lease ${lease.id} for ${lease.source} in ${JSON.stringify(lease.scope)}?`) || session !== epoch) return false;
        await api('/v1/leases/' + encodeURIComponent(lease.id), undefined, 'DELETE'); print('lease-result', { revoked: lease.id }); await listLeases();
      });
    }
    if (!leases?.length) card('lease-list', 'lease', 'No active leases', 'No active leases in the configured scope.');
  }
  action('list-leases', listLeases);
})();
