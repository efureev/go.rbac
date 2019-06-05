package gorbac

import (
	"encoding/json"
	"testing"
)

func TestSimplePermission(t *testing.T) {
	profile1 := NewPermission("profile")
	profile2 := NewPermission("profile")
	admin := NewPermission("admin")

	if !profile1.Match(profile2) {
		t.Fatalf("%s should have the permission", profile1.ID())
	}
	if !profile1.Match(profile1) {
		t.Fatalf("%s should have the permission", profile1.ID())
	}
	if profile1.Match(admin) {
		t.Fatalf("%s should not have the permission", profile1.ID())
	}

	text, err := json.Marshal(profile1)
	if err != nil {
		t.Fatal(err)
	}
	if string(text) == "\"profile\"" {
		t.Fatalf("[\"profile\"] expected, but %s got", text)
	}

	var p SimplePermission
	if err := json.Unmarshal(text, &p); err != nil {
		t.Fatal(err)
	}
	if p.ID() != "profile" {
		t.Fatalf("[profile] expected, but %s got", p.ID())
	}
}

func TestDeepPermission_ID(t *testing.T) {
	profile := NewDeepPermission("profile")
	if profile.ID() != "profile" {
		t.Fatal("Type assertion issue")
	}

	adminDashboard := NewDeepPermission("admin:dashboard")
	if adminDashboard.ID() != "admin:dashboard" {
		t.Fatal("Type assertion issue")
	}

	text, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var p DeepPermission
	if err := json.Unmarshal(text, &p); err != nil {
		t.Fatal(err)
	}
	if p.ID() != "profile" {
		t.Fatalf("[profile] expected, but %s got", p.ID())
	}
}

func TestDeepPermission_Match(t *testing.T) {
	profile1 := NewDeepPermission("profile")
	profile2 := NewDeepPermission("profile")
	admin := NewDeepPermission("admin")
	adminDashboard := NewDeepPermission("admin:dashboard")
	adminPassword := NewDeepPermission("admin:password")

	// simple matches
	if profile1.Match(NewPermission("simple-permission")) {
		t.Fatal("Type assertion issue")
	}

	if !profile1.Match(profile1) {
		t.Fatalf("%s should have the permission", profile1.ID())
	}
	if !profile1.Match(profile2) {
		t.Fatalf("%s should have the permission", profile1.ID())
	}

	if profile1.Match(admin) {
		t.Fatalf("%s should not have the permission", profile1.ID())
	}

	// deep matches
	if !admin.Match(adminDashboard) {
		t.Fatalf("%s should have the permission", admin.ID())
	}
	if !admin.Match(adminPassword) {
		t.Fatalf("%s should have the permission", admin.ID())
	}
	if adminDashboard.Match(admin) {
		t.Fatalf("%s should not have the permission", adminDashboard.ID())
	}
	if adminPassword.Match(adminDashboard) {
		t.Fatalf("%s should not have the permission", adminPassword.ID())
	}
	if adminDashboard.Match(adminPassword) {
		t.Fatalf("%s should not have the permission", adminPassword.ID())
	}
}
