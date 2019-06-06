package main

import (
	"github.com/efureev/go.rbac"
	"log"
	"strings"
)

var rbac = gorbac.New()

func init() {
	loadRoles()
}

var rolesPermissions = map[string][]string{
	`observer`: {
		`task:read`,
		`user:read`,
		`user-self:read`,
		`user-self:update`,
	},
	`reporter`: {
		`task:create`,
		`task:read`,
		`user-self:read`,
		`user-self:update`,
	},
	`moderator`: {
		`task`,
	},
	`admin`: {
		`user`,
	},
	`root`: {
		`system`,
	},
}

var rolesTree = map[string]string{
	`observer`:  `moderator`,
	`reporter`:  `moderator`,
	`moderator`: `admin`,
	`admin`:     `root`,
}

func main() {

	h := func(r gorbac.Role, parents []string) error {
		log.Printf("- Role: %v", r.ID())
		permissions := make([]string, 0)
		for _, p := range r.Permissions() {
			permissions = append(permissions, p.ID())
		}
		log.Printf("\tPermission: %v", permissions)
		log.Printf("\tParents: %v", parents)

		return nil
	}

	gorbac.Walk(rbac, h)

	granted(`root`, `task:read`)
	granted(`root`, `task`)
	granted(`root`, `task:delete`)
	granted(`root`, `user-self:read`)
	granted(`root`, `user`)
	granted(`root`, `user:read`)
	granted(`root`, `user:delete`)
	granted(`root`, `user:delete`)

	granted(`reporter`, `task:create`)
	granted(`reporter`, `user-self:read`)
	accessDeny(`reporter`, `task`)
	accessDeny(`reporter`, `user:read`)

	accessDeny(`moderator`, `system`)
	accessDeny(`admin`, `system`)
	accessDeny(`admin`, `das`)

}

func granted(role, permission string) {
	if rbac.IsGranted(role, gorbac.NewDeepPermission(permission), nil) {
		log.Printf(`role %s accept permission %s`, strings.ToUpper(role), strings.ToUpper(permission))
	} else {
		log.Fatalf(`role %s deny permission %s`, strings.ToUpper(role), strings.ToUpper(permission))
	}
}

func accessDeny(role, permission string) {
	if rbac.IsGranted(role, gorbac.NewDeepPermission(permission), nil) {
		log.Fatalf(`role %s accept permission %s`, strings.ToUpper(role), strings.ToUpper(permission))
	} else {
		log.Printf(`role %s deny permission %s`, strings.ToUpper(role), strings.ToUpper(permission))
	}
}

func loadRoles() {
	for roleName, perms := range rolesPermissions {
		role := gorbac.NewRole(roleName)

		for _, permName := range perms {
			p := gorbac.NewDeepPermission(permName)
			role.Assign(p)
		}

		rbac.Add(role)
	}

	for parentRoleName, roleName := range rolesTree {
		rbac.SetParent(roleName, parentRoleName)
	}
}
