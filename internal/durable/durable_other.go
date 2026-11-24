//go:build !linux

package durable

func barrier(string) error { return nil }
