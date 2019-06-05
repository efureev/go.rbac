# RBAC

[![Build Status](https://travis-ci.org/efureev/go.rbac.svg?branch=master)](https://travis-ci.org/efureev/go.rbac)
[![Maintainability](https://api.codeclimate.com/v1/badges/85716e4950f05fafec2a/maintainability)](https://codeclimate.com/github/efureev/go.rbac/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/85716e4950f05fafec2a/test_coverage)](https://codeclimate.com/github/efureev/go.rbac/test_coverage)
[![codecov](https://codecov.io/gh/efureev/go.rbac/branch/master/graph/badge.svg)](https://codecov.io/gh/efureev/go.rbac)
[![Go Report Card](https://goreportcard.com/badge/github.com/efureev/go.rbac)](https://goreportcard.com/report/github.com/efureev/go.rbac)

Role-Based Access Control

Thus, RBAC has the following model:

* many to many relationship between identities and roles.
* many to many relationship between roles and permissions.
* roles can have a parent role (inheriting permissions).

## Install
```bash
go get -u github.com/efureev/go.rbac
```

## Usage

Although you can adjust the RBAC instance anytime and it's absolutely safe, the library is designed for use with two phases:
- Preparing
- Checking

### Preparing

Import the library:

	import "github.com/efureev/go.rbac"

Get a new instance of RBAC:

	rbac := gorbac.New()

Get some new roles:

	rA := gorbac.NewRole("role-a")
	rB := gorbac.NewRole("role-b")
	rC := gorbac.NewRole("role-c")
	rD := gorbac.NewRole("role-d")
	rE := gorbac.NewRole("role-e")

Get some new permissions:

	pA := gorbac.NewPermission("permission-a")
	pB := gorbac.NewPermission("permission-b")
	pC := gorbac.NewPermission("permission-c")
	pD := gorbac.NewPermission("permission-d")
	pE := gorbac.NewPermission("permission-e")

Add the permissions to roles:

	rA.Assign(pA)
	rB.Assign(pB)
	rC.Assign(pC)
	rD.Assign(pD)
	rE.Assign(pE)

Also, you can implement `gorbac.Role` and `gorbac.Permission` for your own data structure.

After initialization, add the roles to the RBAC instance:

	rbac.Add(rA)
	rbac.Add(rB)
	rbac.Add(rC)
	rbac.Add(rD)
	rbac.Add(rE)

And set the inheritance:

	rbac.SetParent("role-a", "role-b")
	rbac.SetParents("role-b", []string{"role-c", "role-d"})
	rbac.SetParent("role-e", "role-d")

### Checking

Checking the permission is easy:

	if rbac.IsGranted("role-a", pA, nil) &&
		rbac.IsGranted("role-a", pB, nil) &&
		rbac.IsGranted("role-a", pC, nil) &&
		rbac.IsGranted("role-a", pD, nil) {
		fmt.Println("The role-a has been granted permis-a, b, c and d.")
	}


And there are some built-in util-functions: 
[InheritanceCircle](https://godoc.org/github.com/efureev/go.rbac#InheritanceCircle),
[AnyGranted](https://godoc.org/github.com/efureev/go.rbac#AnyGranted), 
[AllGranted](https://godoc.org/github.com/efureev/go.rbac#AllGranted). 
Please [open an issue](https://github.com/efureev/go.rbac/issues/new) for the new built-in requirement.

E.g.:

	rbac.SetParent("role-c", "role-a")
	if err := gorbac.InheritanceCircle(rbac); err != nil {
		fmt.Println("A circle inheratance occurred.")
	}
