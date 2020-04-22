/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <lk/compiler.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

__BEGIN_CDECLS

/**
 *  DOC: API notes
 *
 *  This module defines an API for implementing hardware-specific SPI master
 *  device driver. It is expected that it will be working in conjunction with
 *  higher level service (spimaster) that will make calls described here.
 */

/**
 * struct spi_dev_ctx - opaque SPI device context structure
 *
 * This is an opaque implementation-specific SPI device context structure. It is
 * passed around to indicate active SPI device. This device context structure
 * must uniquely identify SPI device, physical SPI bus it is connected to, and
 * hardware configuration parameters required to talk to the above device.
 *
 * &struct spi_dev_ctx must be allocated by the SPI driver and provided to SPI
 * master service via add_spimaster_service() API as port-specific private data
 * in @priv field of &struct tipc_port.
 *
 * Multiple SPI devices might be connected to the same physical SPI bus. Only
 * one device can be active at a time. Only one client can be connected to a
 * device at a time.
 *
 * spi_seq_*() routines are used to report to SPI device when a sequence of SPI
 * requests begins/ends. spi_req_*() routines are used to invoke individual SPI
 * requests. SPI device driver implementation may choose one of these options:
 *   - execute SPI requests as soon as corresponding spi_req_*() routine is
 *     called
 *   - rely on spi_seq_*() to batch together SPI requests
 * SPI requests must either all be batched or all be executed individually.
 */
struct spi_dev_ctx;

/**
 * spi_is_bus_shared() - check if specified SPI device shares the SPI bus with
 *                       other devices.
 * @dev: SPI device to query
 *
 * If the SPI bus is shared, spi_seq_commit() will not be called for a sequence
 * that would leave CS asserted.
 *
 * Return: true if SPI bus is shared, false otherwise
 */
bool spi_is_bus_shared(struct spi_dev_ctx* dev);

/**
 * spi_req_cs_assert() - assert chip select (CS) for specified SPI device
 * @dev: SPI device to assert CS for
 *
 * Called by SPI master service to assert CS and start a SPI transaction. A SPI
 * transaction is defined as a series of transfers with asserted CS. While SPI
 * transaction is active no other transaction can become active on the same
 * physical SPI bus. These transactions must remain active until CS is
 * deasserted and SPI transaction is stopped for the same device.
 *
 * Activating a SPI device already in active transaction state must result in an
 * error.
 *
 * SPI driver implementation may choose to either (1) execute the request
 * immediately or (2) place the request in a batch that will later be committed
 * by spi_seq_commit().
 *
 * Return: 0 on success, or negative error code otherwise
 */
int spi_req_cs_assert(struct spi_dev_ctx* dev);

/**
 * spi_req_cs_deassert() - deassert chip select (CS) for specified SPI device
 * @dev: SPI device to deassert CS for
 *
 * Called by SPI master service to deassert CS and stop ongoing SPI transaction.
 *
 * Stopping SPI transaction for a device that is not currently in active
 * transaction state must result in an error.
 *
 * SPI driver implementation may choose to either (1) execute the request
 * immediately or (2) place the request in a batch that will later be committed
 * by spi_seq_commit().
 *
 * Return: 0 on success, negative error code otherwise
 */
int spi_req_cs_deassert(struct spi_dev_ctx* dev);

/**
 * spi_req_xfer() - send/receive an array of bytes in device-specific bit order
 * @dev: device to talk to which must be in active transaction state.
 * @tx:  points to array of bytes to send over SPI bus. This parameter could be
 *       NULL to indicate that there are no bytes to send.
 * @rx:  points to memory buffer to store bytes received from device. This
 *       parameter could be NULL to indicate that all received bytes should be
 *       discarded.
 * @len: number of bytes to transmit. It could be 0.
 *
 * Called by SPI master service to send/receive data consisting of specified
 * array of bytes in device-specific on wire bit order. Either or both @rx and
 * @tx could be NULL. Both @tx and @rx could point to the same memory location.
 *
 * @len also controls the number of clock cycles sent the SPI bus. If the
 * word-size is a multiple of 8 bits, the number of SPI clock cycles should be
 * round_up(@len * 8, word-size). Otherwise, details TBD.
 *
 * SPI driver implementation may choose to either (1) execute the request
 * immediately or (2) place the request in a batch that will later be committed
 * by spi_seq_commit().
 *
 * Return: 0 on success, negative error code otherwise
 */
int spi_req_xfer(struct spi_dev_ctx* dev, void* tx, void* rx, size_t len);

/**
 * spi_seq_begin() - begin a sequence of SPI requests for specified SPI device
 * @dev:      SPI device to begin sequence of commands for
 * @num_cmds: number of SPI commands the upcoming sequence
 *
 * Called by SPI master service to begin a sequence of SPI requests.
 *
 * Return: 0 on success, negative error code otherwise
 */
int spi_seq_begin(struct spi_dev_ctx* dev, size_t num_cmds);

/**
 * spi_seq_commit() - commit a sequence of SPI requests for specified SPI device
 * @dev: SPI device to commit sequence of commands for
 *
 * Called by SPI master service to commit a sequence of SPI requests. SPI driver
 * implementations that batch SPI requests must execute the batch at this point.
 *
 * Return: 0 if all command were successful, negative error code otherwise
 */
int spi_seq_commit(struct spi_dev_ctx* dev);

/**
 * spi_seq_abort() - abort a sequence of SPI requests in progress
 * @dev: SPI device to abort sequence of commands for
 *
 * Called by SPI master service to abort a sequence of SPI requests. This
 * routine must restore the state of CS to the state before the sequence has
 * begun.
 */
void spi_seq_abort(struct spi_dev_ctx* dev);

__END_CDECLS
