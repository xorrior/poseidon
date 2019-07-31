// +build darwin

package keys

type DarwinKeyOperation struct {
	Type    string
	KeyData []byte
}

// TODO: Implement function to enumerate macos keychain
func (d *DarwinKeyOperation) KeyType() string {
	return d.Type
}

func (d *DarwinKeyOperation) Data() []byte {
	return d.KeyData
}

func getkeydata(opt Options) (DarwinKeyOperation, error) {
	d := DarwinKeyOperation{}
	return d, nil
}
