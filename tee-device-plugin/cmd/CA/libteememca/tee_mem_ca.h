/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * kunpengsecl licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of
 * the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author: chenzheng
 * Create: 2023-04-23
 * Description: the CA part to call TA for the tee memory.
 */
#ifndef __TEE_MEM_CA_H__
#define __TEE_MEM_CA_H__

// return the free memory of tee, unit is KB
long long GetTeeFreeMem(void);
// return the Capacity memory(physical memory - kernal ) of tee, unit is KB
long long GetTeeCapacityMem(void);

#endif