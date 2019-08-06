// +build darwin
package executeassembly

import "errors"

func executeassembly(assembly *[]byte, params *string)(AssemblyOutput{}, error) {
	return AssemblyOutput{}, errors.New("Not implemented for darwin.")
}