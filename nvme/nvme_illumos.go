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
	"errors"

	"golang.org/x/sys/unix"
)

const (
	// This list isn't exhaustive, only the IOCs we're making use of
	NVME_IOC             = (0x4e564d00) // 'N' << 24 | 'V' << 16 | 'M' << 8
	NVME_IOC_CTRL_INFO   = NVME_IOC | 0
	NVME_IOC_IDENTIFY    = NVME_IOC | 1
	NVME_IOC_GET_LOGPAGE = NVME_IOC | 2
	NVME_IOC_PASSTHRU    = NVME_IOC | 9
	NVME_IOC_NS_INFO     = NVME_IOC | 10
)

type nvmeIocCommon struct {
	nsid    uint32
	drvErr  uint32
	ctrlSct uint32
	ctrlSc  uint32
}

type nvmeIocIdentify struct {
	common nvmeIocCommon
	cns    uint32
	ctrlId uint32
	data   uintptr
}

const (
	NVME_IDENTIFY_MAX_CTRLID  = 0xffff
	NVME_IDENTIFY_MAX_NSID    = 0xffffffff
	NVME_IDENTIFY_MAX_CNS_1v2 = 0xff
	NVME_IDENTIFY_MAX_CNS_1v1 = 0x3
	NVME_IDENTIFY_MAX_CNS     = 0x1
)

type nvmeIocGetLogPage struct {
	common nvmeIocCommon
	csi    uint32
	lid    uint32
	lsp    uint32
	lsi    uint32
	rae    uint32
	lLen   uint64
	offset uint64
	data   uintptr
}

type illumosNVMePassthru struct {
	common  nvmeIocCommon
	opcode  uint32
	timeout uint32 // in seconds
	flags   uint32
	impact  uint32
	cdw0    uint32
	cdw12   uint32
	cdw13   uint32
	cdw14   uint32
	cdw15   uint32
	buflen  uint64
	buf     uintptr
}

// Values for illumosNVMwPassThru.flags
const (
	NVME_PASSTHRU_READ  = 0x01
	NVME_PASSTHRU_WRITE = 0x02
)

func (d *NVMeDevice) nvmeIoctl(cmd int, arg *nvmeIocCommon) error {
	err := unix.IoctlSetInt(d.fd, cmd, int(uintptr(unsafe.Pointer(arg))))

	// TODO: arg may contain an NVMe specific error upon return
	// need to wire that up into this API
	return err
}

func (d *NVMeDevice) nvmePassthru(data *nvmePassthru) error {
	arg := illumosNVMePassthru{
		common: nvmeIocCommon{
			nsid: d.nsid,
		},
		opcode:  data.opcode,
		timeout: data.timeout,
		cdw12:   data.cdw12,
		cdw13:   data.cdw13,
		cdw14:   data.cdw14,
		cdw15:   data.cdw15,
		buflen:  len(*data.buf),
		buf:     uintptr(unsafe.Pointer(&(*data.buf)[0])),
	}

	return d.nvmeIoctl(NVME_IOC_PASSTHRU, &arg.common)
}

// Get the specific log page (and if needed the log page specific id) and place
// the results in buf.
// This is meant to generally be used by other log specific functions, but can be
func (d *NVMeDevice) GetLogPage(page uint8, logSpecificId uint16, buf *[]byte) error {
	arg := nvmeIocGetLogPage{
		common: nvmeIocCommon{
			nsid: d.nsid,
		},
		lid:  page,
		lsi:  logSpecificId,
		lLen: len(*buf),
		data: uintptr(unsafe.Pointer(&(*buf)[0])),
	}

	return d.nvmeIoctl(NVME_IOC_GET_LOGPAGE, &arg.common)
}

// TODO:
// Identify Controller
// Identify Namespace

