// +build windows
package functions

import "github.com/xorrior/poseidon/pkg/utils/winapi"

func isElevated() bool {
	return winapi.IsAdministrator()
}
