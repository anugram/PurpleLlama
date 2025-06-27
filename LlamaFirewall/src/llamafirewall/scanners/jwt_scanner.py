# Copyright (c) ThalesGroup

# pyre-strict
import jwt
import re
import os
from datetime import datetime
from typing import Optional
from .base_scanner import Scanner
from ..llamafirewall_data_types import (
    Message,
    ScanDecision,
    ScanResult,
    ScanStatus,
    Trace,
)

class JWTScanner(Scanner):
    """
    A scanner that checks messages against a list of regex patterns.

    It uses a predefined set of regex patterns for common security concerns.
    """

    def __init__(
        self,
        scanner_name: str = "JWT Scanner",
        config=None,
        block_threshold: float = 1.0
    ):
        # Call parent initializer with required parameters
        super().__init__(scanner_name, block_threshold)
        self.secret_key = os.getenv("JWT_SECRET_KEY", "DEFAULT_SECRET")
        self.algorithms = ["HS256"]
        self.required_claims = ["user_id", "exp"]
        self.extracted_claims: Dict[str, Any] = {}  # Stores validated claims for RAG

    async def scan(
        self, message: Message, past_trace: Trace | None = None
    ) -> ScanResult:
        """
        Scan a message against the default regex patterns.

        Args:
            message: The message to scan
            past_trace: Optional trace of previous messages (not used in this scanner)

        Returns:
            ScanResult: The result of the scan
        """
        token = self._extract_jwt(message)
        if not token:
            return ScanResult(decision=ScanDecision.ALLOW, reason="No JWT found")
        
        try:
            claims = jwt.decode(token, self.secret_key, algorithms=self.algorithms)
            self._validate_claims(claims)
            self.extracted_claims = claims  # Store for RAG access
            return ScanResult(decision=ScanDecision.ALLOW, reason="Valid JWT")
        except jwt.ExpiredSignatureError:
            return ScanResult(decision=ScanDecision.BLOCK, reason="JWT expired", score=1.0)
        except jwt.InvalidTokenError as e:
            return ScanResult(decision=ScanDecision.BLOCK, reason=f"Invalid JWT: {str(e)}", score=1.0)

    def _extract_jwt(self, message: str) -> Optional[str]:
        # Enhanced JWT pattern matching
        jwt_pattern = r"\b(eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)\b"
        match = re.search(jwt_pattern, message)
        return match.group(0) if match else None

    def _validate_claims(self, claims: dict):
        for claim in self.required_claims:
            if claim not in claims:
                raise jwt.InvalidTokenError(f"Missing required claim: {claim}")
        if "exp" in claims and datetime.utcnow() > datetime.utcfromtimestamp(claims["exp"]):
            raise jwt.ExpiredSignatureError("Token expired")