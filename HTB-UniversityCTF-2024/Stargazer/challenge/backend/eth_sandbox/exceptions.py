#!/usr/bin/env python3
# eth_sandbox/exceptions.py

from typing import Optional

class EthSandboxError(Exception):
    """Base class for all exceptions raised by the eth_sandbox package."""
    def __init__(self, message: str, details: Optional[dict] = None):
        """
        Initialize the exception with a message and optional details.

        Args:
            message (str): A description of the error.
            details (dict, optional): Additional information about the error.
        """
        self.details = details or {}
        super().__init__(message)
    
    def __str__(self):
        base_message = super().__str__()
        if self.details:
            return f"[eth_sandbox] {base_message} | Details: {self.details}"
        return base_message

