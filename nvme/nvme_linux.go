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
	"golang.org/x/sys/unix"
)

var (
	// Defined in <linux/nvme_ioctl.h>
	NVME_IOCTL_ADMIN_CMD = ioctl.Iowr('N', 0x41, unsafe.Sizeof(linuxNvmePassthruCommand{}))
)

// Defined in <linux/nvme_ioctl.h> (first 64 bytes refer to NVM Express Base Specification 2.0c,
// figure 88: Common Command Format - Admin and NVM Vendor Specific Commands)
type linuxNvmePassthruCommand struct {
	opcode       uint8
	flags        uint8
	rsvd1        uint16
	nsid         uint32
	cdw2         uint32
	cdw3         uint32
	metadata     uint64
	addr         uint64
	metadata_len uint32
	data_len     uint32
	cdw10        uint32
	cdw11        uint32
	cdw12        uint32
	cdw13        uint32
	cdw14        uint32
	cdw15        uint32
	timeout_ms   uint32
	result       uint32
} // 72 bytes

func (d *NVMeDevice) nvmePassthru(nvmePassThruCmd *cmd) error {
	// TODO need to translate cmd.dir into flags field
	arg := linuxNvmePassthruCommand{
		opcode: cmd.opcode,
		nsid: d.nsid,
		cdw10: cmd.cdw10,
		cdw12: cmd.cdw12,
		cdw13: cmd.cdw13,
		cdw14: cmd.cdw14,
		cdw15: cmd.cdw15,
		addr: uint64(uintptr(unsafe.Pointer(&(*cmd.buf)[0]))),
		data_len: len(*cmd.buf),
		timeout_ms: cmd.timeout * 1000,
	}

	ioc := (3 << 30) | ('N' << 8) | (0x41 << 0) | (72 << 16)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, d.fd, ioc, uintptr(unsafe.Pointer(arg)))
	// XXX We probably should check result as well
	if errno != 0 {
		return errno
	}
	return nil
}

func (d *NVMeDevice) IdentifyController() error {
	// TODO
	return nil
}

// TODO: IdentifyNamespace

func (d *NVMeDevice) GetLogPage(page uint8, logSpecificId uint16, buf *[]byte) error {
	cmd := nvmePassthruCommand{
		opcode:   NVME_ADMIN_GET_LOG_PAGE,
		nsid:     d.nsid,
		dir:      NVME_PT_DIR_READ,
		cdw10:    uint32(page) | uint32(logSpecificId) << 8,
		cdw10:    uint32(logID) | (((uint32(bufLen) / 4) - 1) << 16),
		buf:      buf,
	}

	return d.nvmePassThru(&cmd)
}
