// Copyright 2017-2022 Daniel Swarbrick. All rights reserved.
// Copyright 2024 RackTop Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nvme

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"unsafe"
)

// Base 3.1.3.2 Version numbers
// (values of NvmeIdentController.Ver)
const (
	NVME_VERSION_1_0   = 0x00010000
	NVME_VERSION_1_1   = 0x00010100
	NVME_VERSION_1_2   = 0x00010200
	NVME_VERSION_1_2_1 = 0x00010201
	NVME_VERSION_1_3   = 0x00010300
	NVME_VERSION_1_4   = 0x00010400
	NVME_VERSION_2_0   = 0x00020000
)

// Base 5.17.2.1 Figure 275 - NVME Controller types
// (values of NvmeIdentController.Cntrltype)
const (
	NVME_CONTROLLER_UNKNOWN   = 0
	NVME_CONTROLLER_IO        = 1
	NVME_CONTROLLER_DISCOVERY = 3
	NVME_CONTROLLER_ADMIN     = 4
	// Others reserved
)

// Base 5.17.2.1 - NVME Optional Admin Command Support Values
// (values of NvmeIdentController.Oacs)
const (
	NVME_OACS_LOCKDOWN       = (1 << 10)
	NVME_OACS_GET_LBA_STATUS = (1 << 9)
	NVME_OACS_DB_BUF_CONFIG  = (1 << 8)
	NVME_OACS_VIRT_MGMT      = (1 << 7)
	NVME_OACS_MI             = (1 << 6)
	NVME_OACS_DIRECTIVES     = (1 << 5)
	NVME_OACS_SELF_TEST      = (1 << 4)
	NVME_OACS_NS_MGMT        = (1 << 3)
	MVME_OACS_FW_COMMIT      = (1 << 2)
	NVME_OACS_FORMAT_NVM     = (1 << 1)
	NVME_OACS_SECURITY       = (1 << 0)
)

const (
	NVME_PT_DIR_READ  = 1
	NVME_PT_DIR_WRITE = 2
)

// NVMe op codes (not exhaustive -- just the ones we're using)
const (
	NVME_OP_RESV_REGISTER = 0x0d
	NVME_OP_RESV_REPORT   = 0x0e
	NVME_OP_RESV_ACQUIRE  = 0x11
	NVME_OP_RECV_RELEASE  = 0x15
	NVME_OP_SECURITY_SEND = 0x81
	NVME_OP_SECURITY_RECV = 0x82
)

// illumos and Linux have different definitions for their passthrough
// ioctls with Linux basically just passing through the entire raw
// NVMe command, while illumos takes a more measured approach only
// allowing certain fields to be set for safety reasons. For now, we
// define our own passthrough struct that is a subset of both (but sufficient
// for our purposes) and translate it into the OS-specific version
// as needed.
type nvmePassthru struct {
	opcode  uint8
	dir     uint8
	nsid    uint32
	timeout uint32 // in seconds
	cdw10   uint32
	cdw12   uint32
	cdw13   uint32
	cdw14   uint32
	cdw15   uint32
	buf     *[]byte
}

// NVMe has the notion of namespaces which can be thought of as internal
// partitions (vs. partitioning where the OS manages mapping LBAs within a
// parition into actual drive LBAs -- with namespaces the NVMe device itself is
// effectively doing this). Thus each namespace appears as a separate device in
// the OS.
//
// Some operations are targeted to the controller (and not a particular
// namespace) while others must specify a namespace. An NVMeDevice refers to a
// specific namespace on an NVMe controller.
//
// On illumos, there is a separate device node for the NVMe controller, and we
// must issue NVMe specific ioctls to the controller device (and specify the
// namespace of the corresponding disk device we wish to target). Thankfully,
// the NVMe blkdev disks devices are children of the NVMe controller device in
// the device tree, so it's fairly simple to locate the corresponding controller
// for a given disk device.
//
// On Linux, it appears the disk device will accept NVMe ioctls and we don't
// need to worry about opening the controller device (though this still needs
// to be tested).
type NVMeDevice struct {
	Name string
	fd   int
	nsid uint32
}

func NewNVMeDevice(name string) *NVMeDevice {
	return &NVMeDevice{name, -1}
}

func (d *NVMeDevice) Open() (err error) {
	d.fd, err = unix.Open(d.Name, unix.O_RDWR, 0600)
	return err
}

func (d *NVMeDevice) Close() error {
	return unix.Close(d.fd)
}

func (d *NVMeDevice) IfSend(proto byte, protoSpecific uint16, buf []byte) error {
	pt := nvmePassthru{
		opcode:  NVME_OP_SECURITY_SEND,
		dir:     NVME_PT_DIR_WRITE,
		nsid:    d.nsid,
		timeout: 1,
		cdw10:   (proto << 24) | (protoSpecific << 16),
		buf:     &buf,
	}

	return d.nvmePassthru(&pt)
}

func (d *NVMeDevice) IfRecv(proto byte, protoSpecific uint16, buf []byte) ([]byte, error) {
	pt := nvmePassthru{
		opcode:  NVME_OP_SECURITY_RECV,
		dir:     NVME_PT_DIR_READ,
		nsid:    d.nsid,
		timeout: 1,
		cdw10:   (proto << 24) | (protoSpecific << 16),
		buf:     &buf,
	}

	return buf, d.nvmePassthru(&pt)
}

// XXX This needs to be moved to an OS specific implementation (and just
// return the controller struct
func (d *NVMeDevice) IdentifyController(w io.Writer) (NVMeController, error) {
	var buf [4096]byte

	cmd := nvmePassthruCommand{
		opcode:   NVME_ADMIN_IDENTIFY,
		nsid:     0, // Namespace 0, since we are identifying the controller
		addr:     uint64(uintptr(unsafe.Pointer(&buf[0]))),
		data_len: uint32(len(buf)),
		cdw10:    1, // Identify controller
	}

	if err := ioctl.Ioctl(uintptr(d.fd), NVME_IOCTL_ADMIN_CMD, uintptr(unsafe.Pointer(&cmd))); err != nil {
		return NVMeController{}, err
	}

	fmt.Fprintf(w, "NVMe call: opcode=%#02x, size=%#04x, nsid=%#08x, cdw10=%#08x\n",
		cmd.opcode, cmd.data_len, cmd.nsid, cmd.cdw10)

	var idCtrlr nvmeIdentController

	binary.Read(bytes.NewBuffer(buf[:]), NativeEndian, &idCtrlr)

	controller := NVMeController{
		VendorID:        idCtrlr.VendorID,
		ModelNumber:     string(idCtrlr.ModelNumber[:]),
		SerialNumber:    string(bytes.TrimSpace(idCtrlr.SerialNumber[:])),
		FirmwareVersion: string(idCtrlr.Firmware[:]),
		MaxDataXferSize: 1 << idCtrlr.Mdts,
		// Convert IEEE OUI ID from big-endian
		OUI:         uint32(idCtrlr.IEEE[0]) | uint32(idCtrlr.IEEE[1])<<8 | uint32(idCtrlr.IEEE[2])<<16,
		SecureProto: false,
	}

	// Note this just indicates of the Security Send / Security Receive commands
	// are supported. SED support must be determined by checking the list
	// security protocols supported (and probably best done by the SED code
	// itself).
	if idCtrl.oacs&0x01 == 0x01 {
		controller.SecureProto = true
	}

	fmt.Fprintln(w)
	controller.Print(w)

	for _, ps := range idCtrlr.Psd {
		if ps.MaxPower > 0 {
			fmt.Fprintf(w, "%+v\n", ps)
		}
	}

	return controller, nil
}

// XXX This needs to be replaced so it just returns the identify struct
func (d *NVMeDevice) IdentifyNamespace(w io.Writer, namespace uint32) error {
	var buf [4096]byte

	cmd := nvmePassthruCommand{
		opcode:   NVME_ADMIN_IDENTIFY,
		nsid:     namespace,
		addr:     uint64(uintptr(unsafe.Pointer(&buf[0]))),
		data_len: uint32(len(buf)),
		cdw10:    0,
	}

	if err := ioctl.Ioctl(uintptr(d.fd), NVME_IOCTL_ADMIN_CMD, uintptr(unsafe.Pointer(&cmd))); err != nil {
		return err
	}

	fmt.Fprintf(w, "NVMe call: opcode=%#02x, size=%#04x, nsid=%#08x, cdw10=%#08x\n",
		cmd.opcode, cmd.data_len, cmd.nsid, cmd.cdw10)

	var ns nvmeIdentNamespace

	binary.Read(bytes.NewBuffer(buf[:]), NativeEndian, &ns)

	fmt.Fprintf(w, "Namespace %d size: %d sectors\n", namespace, ns.Nsze)
	fmt.Fprintf(w, "Namespace %d utilisation: %d sectors\n", namespace, ns.Nuse)

	return nil
}

// XXX This might be better moved to a separate package for use as a cmdline
// diagnostic
func (d *NVMeDevice) PrintSMART(w io.Writer) error {
	buf := make([]byte, 512)

	// Read SMART log
	if err := d.readLogPage(0x02, &buf); err != nil {
		return err
	}

	var sl nvmeSMARTLog

	binary.Read(bytes.NewBuffer(buf[:]), NativeEndian, &sl)

	unitsRead := le128ToBigInt(sl.DataUnitsRead)
	unitsWritten := le128ToBigInt(sl.DataUnitsWritten)
	unit := big.NewInt(512 * 1000)

	fmt.Fprintln(w, "\nSMART data follows:")
	fmt.Fprintf(w, "Critical warning: %#02x\n", sl.CritWarning)
	fmt.Fprintf(w, "Temperature: %d° Celsius\n",
		(uint16(sl.Temperature[0])|uint16(sl.Temperature[1])<<8)-273) // Kelvin to degrees Celsius
	fmt.Fprintf(w, "Avail. spare: %d%%\n", sl.AvailSpare)
	fmt.Fprintf(w, "Avail. spare threshold: %d%%\n", sl.SpareThresh)
	fmt.Fprintf(w, "Percentage used: %d%%\n", sl.PercentUsed)
	fmt.Fprintf(w, "Data units read: %d [%s]\n",
		unitsRead, formatBigBytes(new(big.Int).Mul(unitsRead, unit)))
	fmt.Fprintf(w, "Data units written: %d [%s]\n",
		unitsWritten, formatBigBytes(new(big.Int).Mul(unitsWritten, unit)))
	fmt.Fprintf(w, "Host read commands: %d\n", le128ToBigInt(sl.HostReads))
	fmt.Fprintf(w, "Host write commands: %d\n", le128ToBigInt(sl.HostWrites))
	fmt.Fprintf(w, "Controller busy time: %d\n", le128ToBigInt(sl.CtrlBusyTime))
	fmt.Fprintf(w, "Power cycles: %d\n", le128ToBigInt(sl.PowerCycles))
	fmt.Fprintf(w, "Power on hours: %d\n", le128ToBigInt(sl.PowerOnHours))
	fmt.Fprintf(w, "Unsafe shutdowns: %d\n", le128ToBigInt(sl.UnsafeShutdowns))
	fmt.Fprintf(w, "Media & data integrity errors: %d\n", le128ToBigInt(sl.MediaErrors))
	fmt.Fprintf(w, "Error information log entries: %d\n", le128ToBigInt(sl.NumErrLogEntries))

	return nil
}

// XXX this can be removed
func (d *NVMeDevice) readLogPage(logID uint8, buf *[]byte) error {
	bufLen := len(*buf)

	if (bufLen < 4) || (bufLen > 0x4000) || (bufLen%4 != 0) {
		return fmt.Errorf("invalid buffer size")
	}

	cmd := nvmePassthruCommand{
		opcode:   NVME_ADMIN_GET_LOG_PAGE,
		nsid:     0xffffffff, // FIXME
		addr:     uint64(uintptr(unsafe.Pointer(&(*buf)[0]))),
		data_len: uint32(bufLen),
		cdw10:    uint32(logID) | (((uint32(bufLen) / 4) - 1) << 16),
	}

	return ioctl.Ioctl(uintptr(d.fd), NVME_IOCTL_ADMIN_CMD, uintptr(unsafe.Pointer(&cmd)))
}

type NvmeIdentController struct {
	VendorID     uint16   // PCI Vendor ID
	Ssvid        uint16   // PCI Subsystem Vendor ID
	SerialNumber [20]byte // Serial Number
	ModelNumber  [40]byte // Model Number
	Firmware     [8]byte  // Firmware Revision
	Rab          uint8    // Recommended Arbitration Burst
	IEEE         [3]byte  // IEEE OUI Identifier
	Cmic         uint8    // Controller Multi-Path I/O and Namespace Sharing Capabilities
	Mdts         uint8    // Maximum Data Transfer Size
	Cntlid       uint16   // Controller ID
	Ver          uint32   // Version
	Rtd3r        uint32   // RTD3 Resume Latency
	Rtd3e        uint32   // RTD3 Entry Latency
	Oaes         uint32   // Optional Asynchronous Events Supported
	Ctratt       uint32   // Controller attributes
	Rrls         uint16   // Read Recovery Levels
	Rsvd102      [9]byte
	Cntrltype    uint8     // Controller Type
	Fguid        [16]byte  // FRU Guid
	Crdt1        uint16    // Command Retry Delay Time 1
	Crdt2        uint16    // Command Retry Delay Time 2
	Crdt3        uint16    // Command Retry Delay Time 3
	Rsvd134      [106]byte // ...
	Rsvd240      [13]byte
	Vwci         uint8                   // VPD Write Cycle Information
	Mec          uint8                   // Management Endpoint Capabilities
	Oacs         uint16                  // Optional Admin Command Support
	Acl          uint8                   // Abort Command Limit
	Aerl         uint8                   // Asynchronous Event Request Limit
	Frmw         uint8                   // Firmware Updates
	Lpa          uint8                   // Log Page Attributes
	Elpe         uint8                   // Error Log Page Entries
	Npss         uint8                   // Number of Power States Support
	Avscc        uint8                   // Admin Vendor Specific Command Configuration
	Apsta        uint8                   // Autonomous Power State Transition Attributes
	Wctemp       uint16                  // Warning Composite Temperature Threshold
	Cctemp       uint16                  // Critical Composite Temperature Threshold
	Mtfa         uint16                  // Maximum Time for Firmware Activation
	Hmpre        uint32                  // Host Memory Buffer Preferred Size
	Hmmin        uint32                  // Host Memory Buffer Minimum Size
	Tnvmcap      [16]byte                // Total NVM Capacity
	Unvmcap      [16]byte                // Unallocated NVM Capacity
	Rpmbs        uint32                  // Replay Protected Memory Block Support
	Rsvd316      [196]byte               // ...
	Sqes         uint8                   // Submission Queue Entry Size
	Cqes         uint8                   // Completion Queue Entry Size
	Rsvd514      [2]byte                 // (defined in NVMe 1.3 spec)
	Nn           uint32                  // Number of Namespaces
	Oncs         uint16                  // Optional NVM Command Support
	Fuses        uint16                  // Fused Operation Support
	Fna          uint8                   // Format NVM Attributes
	Vwc          uint8                   // Volatile Write Cache
	Awun         uint16                  // Atomic Write Unit Normal
	Awupf        uint16                  // Atomic Write Unit Power Fail
	Nvscc        uint8                   // NVM Vendor Specific Command Configuration
	Rsvd531      uint8                   // ...
	Acwu         uint16                  // Atomic Compare & Write Unit
	Rsvd534      [2]byte                 // ...
	Sgls         uint32                  // SGL Support
	Rsvd540      [1508]byte              // ...
	Psd          [32]nvmeIdentPowerState // Power State Descriptors
	Vs           [1024]byte              // Vendor Specific
} // 4096 bytes

// Some helper functions to extract values from NvmeIdentController. These aren't
// exhaustive, but are merely the things that we find useful.

func (c *NvmeIdentController) GetSerial() string {
	return string(c.SerialNumber[:])
}

func (c *NvmeIdentController) GetModel() string {
	return string(c.ModelNumber[:])
}

func (c *NvmeIdentController) GetFirmware() string {
	return string(c.Firmware[:])
}

func (c *NvmeIdentController) HasSecureIO() bool {
	return (c.Oacs & NVME_OACS_SECURITY) != 0
}

type nvmeIdentPowerState struct {
	MaxPower        uint16 // Centiwatts
	Rsvd2           uint8
	Flags           uint8
	EntryLat        uint32 // Microseconds
	ExitLat         uint32 // Microseconds
	ReadTput        uint8
	ReadLat         uint8
	WriteTput       uint8
	WriteLat        uint8
	IdlePower       uint16
	IdleScale       uint8
	Rsvd19          uint8
	ActivePower     uint16
	ActiveWorkScale uint8
	Rsvd23          [9]byte
}

type NvmeLBAF struct {
	Ms uint16
	Ds uint8
	Rp uint8
}

// Cmdset 4.1.5.1
// Note that some of these fields may be zero depending on
// the NVMe version supported by the controller.
type NvmeIdentNamespace struct {
	Nsze     uint64   // NS size in blocks
	Ncap     uint64   // NS capacity
	Nuse     uint64   // NS utilization
	Nsfeat   uint8    // NS features
	Nlbaf    uint8    // # of supported LBA formats
	Flbas    uint8    // Formatted LBA Size
	Mc       uint8    // Metadata capabilites
	Dpc      uint8    // Dataprotection capabilites
	Dps      uint8    // Dataprotection settings
	Nmic     uint8    // Multipath/sharing capabilities
	Rescap   uint8    // Reservation capabilities
	Fpi      uint8    // Format progress indicator
	Dlfeat   uint8    // Deallocate logical block features
	Nawun    uint16   // Atomic write unit normal
	Nawupf   uint16   // Atomic write uint fail
	Nacwu    uint16   // Atomic compare and write unit
	Nabsn    uint16   // Atomic boundary size normal
	Nabo     uint16   // Atomic boundary offset
	Nabspf   uint16   // Atomic boundary size fail
	Noiob    uint16   // Optimal I/O boundary
	Nvmcap   [16]byte // Total size of NVM allocated to NS
	Npwg     uint16   // Preferred Write Granularity
	Npwa     uint16   // Preferred write alignment
	Npdg     uint16   // Preferred deallocate granularity
	Npda     uint16   // Preferred deallocate alignment
	Nows     uint16   // Optimal write size
	Mssrl    uint16   // Maximum single source range length
	Mcl      uint32   // Maximum copy length
	Msrc     uint8    // Maximum source range count
	Rsvd     [11]byte
	Anagrpid uint32 // ANA Group Identifier
	Rsvd1    [3]byte
	Nsattr   uint8        // NS Attributes
	Nvmsetid uint16       // NVM Set Identifier
	Endgid   uint16       // Endurance group identifier
	Nguid    [16]byte     // NS GUID
	EUI64    [8]byte      // NS EUI64
	Lbaf     [16]NvmeLBAF // LBA 0-63 Format support
	Rsvd192  [192]byte
	Vs       [3712]byte
} // 4096 bytes

type NVMeSMARTLog struct {
	CritWarning      uint8
	Temperature      [2]uint8
	AvailSpare       uint8
	SpareThresh      uint8
	PercentUsed      uint8
	Rsvd6            [26]byte
	DataUnitsRead    [16]byte
	DataUnitsWritten [16]byte
	HostReads        [16]byte
	HostWrites       [16]byte
	CtrlBusyTime     [16]byte
	PowerCycles      [16]byte
	PowerOnHours     [16]byte
	UnsafeShutdowns  [16]byte
	MediaErrors      [16]byte
	NumErrLogEntries [16]byte
	WarningTempTime  uint32
	CritCompTime     uint32
	TempSensor       [8]uint16
	Rsvd216          [296]byte
} // 512 bytes

// TODO: Add some helper methods for decoding values (e.g. [16]byte -> uint128)
// and it would probably be nice to add some methods for requesting specific
// log pages that call d.GetLogPage() and then translate the raw buf into
// the corresponding struct for the log page

// TODO: Reservation commands
