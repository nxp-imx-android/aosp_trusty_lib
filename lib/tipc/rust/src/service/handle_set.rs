/*
 * Copyright (C) 2021 The Android Open Source Project
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

use alloc::rc::Rc;
use core::array;
use core::fmt;
use core::ptr;
use log::error;

use super::{Channel, Dispatcher};
use crate::sys;
use crate::{Handle, Result, TipcError};

/// A handle set is a collection of tipc service ports, along with their
/// respective connections to clients.
///
/// A handle set is specific to a particular service, with a fixed set of ports
/// and a maximum number of allowed concurrent connections
/// `MAX_CONNECTION_COUNT`.
pub(super) struct HandleSet<
    D: Dispatcher,
    const PORT_COUNT: usize,
    const MAX_CONNECTION_COUNT: usize,
> {
    ports: [Rc<Channel<D>>; PORT_COUNT],
    connections: [Option<Rc<Channel<D>>>; MAX_CONNECTION_COUNT],
    connection_count: usize,
    handle: Handle,
}

impl<D: Dispatcher, const PORT_COUNT: usize, const MAX_CONNECTION_COUNT: usize>
    HandleSet<D, PORT_COUNT, MAX_CONNECTION_COUNT>
{
    pub fn try_new(ports: [Rc<Channel<D>>; PORT_COUNT]) -> Result<Self> {
        // SAFETY: syscall, return value is either a negative error code or a
        // valid handle.
        let rc = unsafe { trusty_sys::handle_set_create() };
        if rc < 0 {
            Err(TipcError::from_uapi(rc))
        } else {
            for port in &ports {
                if !port.is_port() {
                    return Err(TipcError::InvalidData);
                }
            }

            let handle_set = Self {
                ports,
                connections: array::from_fn(|_| None),
                connection_count: 0,
                handle: Handle::from_raw(rc as i32)?,
            };

            for port in &handle_set.ports {
                handle_set.do_set_ctrl(
                    sys::HSET_ADD as u32,
                    trusty_sys::uevent::ALL_EVENTS,
                    port,
                )?;
            }

            Ok(handle_set)
        }
    }

    /// Register a new connection in this handle set
    ///
    /// This function does not need to be unsafe because we do not dereference
    /// the opaque pointer. However, the handler must agree on the type of this
    /// cookie.
    pub fn add_connection(&mut self, connection: Rc<Channel<D>>) -> Result<()> {
        if !connection.is_connection() {
            return Err(TipcError::InvalidData);
        }

        // We should never exceed this count since the port is masked when
        // we hit the max
        assert!(!self.at_max_connections(), "Too many connections");
        self.do_set_ctrl(sys::HSET_ADD as u32, trusty_sys::uevent::ALL_EVENTS, &connection)?;
        let slot_occupied = self.connections[self.connection_count].replace(connection).is_some();
        assert!(!slot_occupied, "Expected unoccupied connection slot at {}", self.connection_count);
        self.connection_count += 1;

        if self.at_max_connections() {
            self.mask_all_ports();
        }
        Ok(())
    }

    /// Wait for an event on this handle set
    ///
    /// Waits for `timeout` milliseconds or indefinitely if `None`.
    pub fn wait(&self, timeout: Option<u32>) -> Result<trusty_sys::uevent> {
        self.handle.wait(timeout)
    }

    /// Close a connection in this handle set.
    ///
    /// This should only be used to close active connections, not ports.
    pub fn close(&mut self, connection: Rc<Channel<D>>) {
        assert!(connection.is_connection());

        let _ = self
            .connections
            .iter_mut()
            .find(|c| c.as_ref() == Some(&connection))
            .expect("Could not find connection")
            .take();
        self.do_set_ctrl(sys::HSET_DEL as u32, 0, &connection).unwrap_or_else(|e| {
            error!("Failed to remove channel {:?} from handle set: {:?}", connection, e)
        });

        // This should be the last instance of the channel
        assert_eq!(Rc::strong_count(&connection), 1);
        let _ = connection;

        if self.at_max_connections() {
            self.unmask_all_ports();
        }

        self.connection_count -= 1;
    }

    fn mask_all_ports(&self) {
        for port in &self.ports {
            self.do_set_ctrl(sys::HSET_MOD as u32, 0, &port).expect("Failed to mask port");
        }
    }

    fn unmask_all_ports(&self) {
        for port in &self.ports {
            self.do_set_ctrl(sys::HSET_MOD as u32, trusty_sys::uevent::ALL_EVENTS, &port)
                .expect("Failed to unmask port");
        }
    }

    fn do_set_ctrl(&self, cmd: u32, event: u32, channel: &Rc<Channel<D>>) -> Result<()> {
        let mut uevt = trusty_sys::uevent {
            handle: channel.handle().as_raw_fd(),
            event,
            cookie: if cmd == sys::HSET_DEL as u32 {
                ptr::null_mut()
            } else {
                Channel::into_opaque_ptr(Rc::downgrade(channel))
            },
        };
        // SAFETY: syscall. The uevent pointer points to a correctly initialized
        // structure that is borrowed and valid across the call. The handle for
        // the handle set is valid for the same lifetime as self, so will remain
        // valid at least as long as the channel being added/modified.
        let rc = unsafe { trusty_sys::handle_set_ctrl(self.handle.as_raw_fd(), cmd, &mut uevt) };
        if rc < 0 {
            Err(TipcError::from_uapi(rc))
        } else {
            Ok(())
        }
    }

    fn at_max_connections(&self) -> bool {
        self.connection_count >= MAX_CONNECTION_COUNT
    }
}

impl<D: Dispatcher, const PORT_COUNT: usize, const MAX_CONNECTION_COUNT: usize> fmt::Debug
    for HandleSet<D, PORT_COUNT, MAX_CONNECTION_COUNT>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HandleSet: [{:?}", self.ports)
    }
}
