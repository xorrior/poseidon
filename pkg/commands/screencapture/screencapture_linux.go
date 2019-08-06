// +build linux

package screencapture

import "errors"

//LinuxScreenshot - struct for screenshot data
type LinuxScreenshot struct {
	MonitorIndex   int
	ScreenshotData []byte
}

//Monitor - Darwin subclass method to return the monitor index
func (d *LinuxScreenshot) Monitor() int {
	return d.MonitorIndex
}

//Data - Darwin subclass method to return the raw png data
func (d *LinuxScreenshot) Data() []byte {
	return d.ScreenshotData
}

func getscreenshot() ([]ScreenShot, error) {
	return nil, errors.New("not implemented for linux")
}
