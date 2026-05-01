#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
xttps_protocol_handler.py — XTTPS Custom Protocol Handler

This module provides a comprehensive protocol handler for the XTTPS custom protocol.
It manages:
- Protocol initialization and lifecycle
- Message routing and dispatching
- Protocol state machine
- Error handling and recovery
- Protocol extensions and callbacks

Usage:
    handler = XTTPSProtocolHandler()
    handler.initialize()
    handler.route_message(message_type, payload)
"""

import logging
import time
import enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Any
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# ============================================================
# Protocol State Definitions
# ============================================================

class ProtocolState(enum.Enum):
    """XTTPS Protocol States"""
    IDLE = "idle"
    INITIALIZING = "initializing"
    HANDSHAKING = "handshaking"
    ESTABLISHED = "established"
    DATA_TRANSFER = "data_transfer"
    RENEGOTIATION = "renegotiation"
    CLOSING = "closing"
    CLOSED = "closed"
    ERROR = "error"


class MessageType(enum.Enum):
    """XTTPS Message Types"""
    INIT_REQ = "init_req"
    INIT_RESP = "init_resp"
    HANDSHAKE_REQ = "handshake_req"
    HANDSHAKE_RESP = "handshake_resp"
    DATA = "data"
    ACK = "ack"
    RENEGO_REQ = "renego_req"
    RENEGO_RESP = "renego_resp"
    CLOSE_REQ = "close_req"
    CLOSE_RESP = "close_resp"
    ERROR = "error"


# ============================================================
# Data Structures
# ============================================================

@dataclass
class ProtocolMessage:
    """Represents an XTTPS Protocol Message"""
    message_type: MessageType
    sequence_number: int
    timestamp: float
    payload: bytes
    checksum: Optional[bytes] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary"""
        return {
            "message_type": self.message_type.value,
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp,
            "payload": self.payload.hex() if self.payload else "",
            "checksum": self.checksum.hex() if self.checksum else None,
            "metadata": self.metadata or {}
        }


@dataclass
class ProtocolConfig:
    """XTTPS Protocol Configuration"""
    max_message_size: int = 65536  # 64KB
    handshake_timeout: float = 30.0  # seconds
    data_timeout: float = 300.0  # 5 minutes
    enable_compression: bool = False
    enable_encryption: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0


# ============================================================
# Protocol Handler Base Class
# ============================================================

class ProtocolHandler(ABC):
    """Abstract base class for protocol handlers"""

    @abstractmethod
    def handle_init_request(self, payload: bytes) -> ProtocolMessage:
        """Handle initialization request"""
        pass

    @abstractmethod
    def handle_handshake_request(self, payload: bytes) -> ProtocolMessage:
        """Handle handshake request"""
        pass

    @abstractmethod
    def handle_data(self, payload: bytes) -> ProtocolMessage:
        """Handle data message"""
        pass

    @abstractmethod
    def handle_close_request(self, payload: bytes) -> ProtocolMessage:
        """Handle close request"""
        pass


# ============================================================
# XTTPS Protocol Handler Implementation
# ============================================================

class XTTPSProtocolHandler(ProtocolHandler):
    """
    Main XTTPS Protocol Handler

    Manages the complete XTTPS protocol lifecycle including
    initialization, handshaking, data transfer, and termination.
    """

    def __init__(self, config: Optional[ProtocolConfig] = None):
        """Initialize XTTPS Protocol Handler"""
        self.config = config or ProtocolConfig()
        self.state = ProtocolState.IDLE
        self.sequence_number = 0
        self.handlers: Dict[MessageType, Callable] = {}
        self.callbacks: Dict[ProtocolState, List[Callable]] = {
            state: [] for state in ProtocolState
        }
        self.message_history: List[ProtocolMessage] = []
        self.state_history: List[tuple] = []
        logger.info("XTTPS Protocol Handler initialized")

    def register_handler(self, message_type: MessageType, handler: Callable) -> None:
        """Register a custom message handler"""
        self.handlers[message_type] = handler
        logger.debug(f"Registered handler for {message_type.value}")

    def register_state_callback(self, state: ProtocolState, callback: Callable) -> None:
        """Register a callback for state transitions"""
        self.callbacks[state].append(callback)
        logger.debug(f"Registered callback for {state.value}")

    def transition_state(self, new_state: ProtocolState) -> None:
        """Transition to a new protocol state"""
        old_state = self.state
        self.state = new_state
        self.state_history.append((time.time(), old_state.value, new_state.value))
        logger.info(f"State transition: {old_state.value} -> {new_state.value}")

        # Execute state callbacks
        for callback in self.callbacks[new_state]:
            try:
                callback(old_state, new_state)
            except Exception as e:
                logger.error(f"Error executing callback: {e}")

    def initialize(self) -> None:
        """Initialize the protocol"""
        logger.info("Initializing XTTPS protocol")
        self.transition_state(ProtocolState.INITIALIZING)
        # Protocol initialization logic here
        self.transition_state(ProtocolState.HANDSHAKING)

    def route_message(self, message: ProtocolMessage) -> Optional[ProtocolMessage]:
        """Route an incoming message to appropriate handler"""
        logger.debug(f"Routing message: {message.message_type.value}")
        self.sequence_number += 1

        # Check if custom handler is registered
        if message.message_type in self.handlers:
            return self.handlers[message.message_type](message.payload)

        # Route to default handlers
        try:
            if message.message_type == MessageType.INIT_REQ:
                response = self.handle_init_request(message.payload)
            elif message.message_type == MessageType.HANDSHAKE_REQ:
                response = self.handle_handshake_request(message.payload)
            elif message.message_type == MessageType.DATA:
                response = self.handle_data(message.payload)
            elif message.message_type == MessageType.CLOSE_REQ:
                response = self.handle_close_request(message.payload)
            else:
                logger.warning(f"Unhandled message type: {message.message_type.value}")
                response = self._create_error_message("Unknown message type")
        except Exception as e:
            logger.error(f"Error routing message: {e}")
            response = self._create_error_message(str(e))

        # Store in history
        self.message_history.append(message)

        return response

    def handle_init_request(self, payload: bytes) -> ProtocolMessage:
        """Handle initialization request"""
        logger.debug("Handling INIT_REQ")
        self.transition_state(ProtocolState.HANDSHAKING)
        return self._create_message(MessageType.INIT_RESP, b"OK")

    def handle_handshake_request(self, payload: bytes) -> ProtocolMessage:
        """Handle handshake request"""
        logger.debug("Handling HANDSHAKE_REQ")
        self.transition_state(ProtocolState.ESTABLISHED)
        return self._create_message(MessageType.HANDSHAKE_RESP, b"HANDSHAKE_COMPLETE")

    def handle_data(self, payload: bytes) -> ProtocolMessage:
        """Handle data message"""
        logger.debug(f"Handling DATA: {len(payload)} bytes")
        
        # Validate payload size
        if len(payload) > self.config.max_message_size:
            return self._create_error_message("Message too large")

        self.transition_state(ProtocolState.DATA_TRANSFER)
        return self._create_message(MessageType.ACK, b"DATA_RECEIVED")

    def handle_close_request(self, payload: bytes) -> ProtocolMessage:
        """Handle close request"""
        logger.debug("Handling CLOSE_REQ")
        self.transition_state(ProtocolState.CLOSING)
        response = self._create_message(MessageType.CLOSE_RESP, b"CLOSING")
        self.transition_state(ProtocolState.CLOSED)
        return response

    def _create_message(self, message_type: MessageType, payload: bytes,
                       metadata: Optional[Dict[str, Any]] = None) -> ProtocolMessage:
        """Create a protocol message"""
        self.sequence_number += 1
        return ProtocolMessage(
            message_type=message_type,
            sequence_number=self.sequence_number,
            timestamp=time.time(),
            payload=payload,
            metadata=metadata or {}
        )

    def _create_error_message(self, error_msg: str) -> ProtocolMessage:
        """Create an error message"""
        self.transition_state(ProtocolState.ERROR)
        return self._create_message(
            MessageType.ERROR,
            error_msg.encode(),
            metadata={"error": error_msg}
        )

    def get_state(self) -> ProtocolState:
        """Get current protocol state"""
        return self.state

    def get_message_history(self) -> List[Dict[str, Any]]:
        """Get message history"""
        return [msg.to_dict() for msg in self.message_history]

    def get_state_history(self) -> List[Dict[str, Any]]:
        """Get state transition history"""
        return [
            {
                "timestamp": timestamp,
                "from_state": from_state,
                "to_state": to_state
            }
            for timestamp, from_state, to_state in self.state_history
        ]

    def reset(self) -> None:
        """Reset protocol handler"""
        logger.info("Resetting XTTPS protocol handler")
        self.state = ProtocolState.IDLE
        self.sequence_number = 0
        self.message_history.clear()
        self.state_history.clear()


# ============================================================
# Protocol Manager
# ============================================================

class ProtocolManager:
    """
    Manages multiple protocol handlers and coordinates communication
    """

    def __init__(self):
        """Initialize protocol manager"""
        self.handlers: Dict[str, XTTPSProtocolHandler] = {}
        logger.info("Protocol Manager initialized")

    def create_handler(self, handler_id: str,
                      config: Optional[ProtocolConfig] = None) -> XTTPSProtocolHandler:
        """Create a new protocol handler"""
        handler = XTTPSProtocolHandler(config)
        self.handlers[handler_id] = handler
        logger.info(f"Created handler: {handler_id}")
        return handler

    def get_handler(self, handler_id: str) -> Optional[XTTPSProtocolHandler]:
        """Get a protocol handler by ID"""
        return self.handlers.get(handler_id)

    def remove_handler(self, handler_id: str) -> None:
        """Remove a protocol handler"""
        if handler_id in self.handlers:
            del self.handlers[handler_id]
            logger.info(f"Removed handler: {handler_id}")

    def list_handlers(self) -> List[str]:
        """List all handler IDs"""
        return list(self.handlers.keys())

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all handlers"""
        return {
            handler_id: {
                "state": handler.get_state().value,
                "messages": len(handler.message_history),
                "sequence": handler.sequence_number
            }
            for handler_id, handler in self.handlers.items()
        }


# ============================================================
# Example Usage and Testing
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("XTTPS Protocol Handler - Example Usage")
    print("=" * 60)

    # Create protocol manager
    manager = ProtocolManager()

    # Create a handler
    handler = manager.create_handler("client-1")
    handler.initialize()

    # Simulate protocol flow
    print("\n[1] Sending INIT_REQ")
    init_msg = ProtocolMessage(
        message_type=MessageType.INIT_REQ,
        sequence_number=1,
        timestamp=time.time(),
        payload=b"INIT_DATA"
    )
    response = handler.route_message(init_msg)
    print(f"    Response: {response.message_type.value}")

    print("\n[2] Sending HANDSHAKE_REQ")
    hs_msg = ProtocolMessage(
        message_type=MessageType.HANDSHAKE_REQ,
        sequence_number=2,
        timestamp=time.time(),
        payload=b"HANDSHAKE_DATA"
    )
    response = handler.route_message(hs_msg)
    print(f"    Response: {response.message_type.value}")

    print("\n[3] Sending DATA")
    data_msg = ProtocolMessage(
        message_type=MessageType.DATA,
        sequence_number=3,
        timestamp=time.time(),
        payload=b"PAYLOAD_DATA" * 100
    )
    response = handler.route_message(data_msg)
    print(f"    Response: {response.message_type.value}")

    print("\n[4] Sending CLOSE_REQ")
    close_msg = ProtocolMessage(
        message_type=MessageType.CLOSE_REQ,
        sequence_number=4,
        timestamp=time.time(),
        payload=b""
    )
    response = handler.route_message(close_msg)
    print(f"    Response: {response.message_type.value}")

    # Print statistics
    print("\n" + "=" * 60)
    print("Protocol Statistics")
    print("=" * 60)
    print(f"Current State: {handler.get_state().value}")
    print(f"Total Messages: {len(handler.message_history)}")
    print(f"Message Sequence: {handler.sequence_number}")

    print("\nState History:")
    for entry in handler.get_state_history():
        print(f"  {entry['from_state']} -> {entry['to_state']}")

    print("\n" + "=" * 60)
