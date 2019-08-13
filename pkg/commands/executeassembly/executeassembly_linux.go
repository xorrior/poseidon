// +build linux
package executeassembly

import "errors"

func executeassembly(assembly *[]byte, params *string, jobKillChan *chan<- int) (AssemblyOutput, error) {
	return AssemblyOutput{}, errors.New("Not implemented for linux.")
}
