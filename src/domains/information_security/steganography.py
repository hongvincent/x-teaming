"""
Steganography Detection Module
Detects hidden messages in images, text, and other media
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import base64

from src.utils.llm_client import LLMClient
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SteganographyAnalysis:
    """Steganography detection result"""

    file_id: str
    hidden_data_detected: bool
    confidence: float
    steganography_type: str
    indicators: List[str]
    extraction_method: Optional[str]
    estimated_payload_size: Optional[int]
    risk_level: str
    timestamp: str


@dataclass
class TextSteganography:
    """Text-based steganography detection"""

    text_id: str
    hidden_message_detected: bool
    technique: str  # whitespace, invisible_chars, unicode, format
    confidence: float
    extracted_data: Optional[str]
    encoding_method: str


@dataclass
class ImageSteganography:
    """Image steganography analysis"""

    image_id: str
    lsb_anomaly: bool
    metadata_hidden_data: bool
    suspicious_patterns: List[str]
    confidence: float
    recommended_tools: List[str]


class SteganographyModule:
    """
    Steganography Detection Module
    Uses LLM to detect hidden information in various media types
    """

    def __init__(self):
        """Initialize steganography module"""
        self.llm_client = LLMClient()
        logger.info("Steganography Module initialized")

    def analyze_text_steganography(self, text: str) -> TextSteganography:
        """
        Detect hidden messages in text

        Args:
            text: Text to analyze for steganography

        Returns:
            TextSteganography: Detection results
        """
        logger.info("Analyzing text for steganography")

        system_message = """You are a steganography detection expert.
Analyze text for hidden information using techniques like:
- Whitespace encoding
- Invisible Unicode characters (zero-width, right-to-left marks)
- First letter of each word/sentence encoding
- Format-based encoding
- Homoglyph substitution"""

        # Analyze text characteristics
        char_analysis = self._analyze_text_characters(text)

        prompt = f"""Analyze this text for steganographic content:

Text:
{text[:1500]}

Character Analysis:
{char_analysis}

Detect hidden messages and provide analysis in JSON format:
{{
    "hidden_message_detected": boolean,
    "technique": "whitespace" | "invisible_chars" | "unicode" | "format" | "acrostic" | "none",
    "confidence": float (0-1),
    "extracted_data": "extracted hidden message or null",
    "encoding_method": "description of encoding method used"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            text_id = f"text_{datetime.now().timestamp()}"

            return TextSteganography(
                text_id=text_id,
                hidden_message_detected=result.get("hidden_message_detected", False),
                technique=result.get("technique", "none"),
                confidence=result.get("confidence", 0.0),
                extracted_data=result.get("extracted_data"),
                encoding_method=result.get("encoding_method", ""),
            )

        except Exception as e:
            logger.error(f"Text steganography analysis failed: {e}")
            return TextSteganography(
                text_id="error",
                hidden_message_detected=False,
                technique="error",
                confidence=0.0,
                extracted_data=None,
                encoding_method=f"Analysis error: {e}",
            )

    def analyze_image_metadata(
        self, image_metadata: Dict[str, Any]
    ) -> ImageSteganography:
        """
        Analyze image metadata for hidden data

        Args:
            image_metadata: Image EXIF and metadata

        Returns:
            ImageSteganography: Analysis results
        """
        logger.info("Analyzing image metadata for steganography")

        system_message = """You are an image forensics expert.
Analyze image metadata for steganographic indicators:
- Hidden data in EXIF fields
- Unusual comment fields
- Modified timestamps
- Suspicious metadata patterns
- LSB (Least Significant Bit) anomalies"""

        metadata_str = "\n".join([f"{k}: {v}" for k, v in image_metadata.items()])

        prompt = f"""Analyze this image metadata for steganography:

Metadata:
{metadata_str}

Provide analysis in JSON format:
{{
    "lsb_anomaly": boolean,
    "metadata_hidden_data": boolean,
    "suspicious_patterns": [list of suspicious patterns found],
    "confidence": float (0-1),
    "recommended_tools": [list of tools for deeper analysis]
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            image_id = f"image_{datetime.now().timestamp()}"

            return ImageSteganography(
                image_id=image_id,
                lsb_anomaly=result.get("lsb_anomaly", False),
                metadata_hidden_data=result.get("metadata_hidden_data", False),
                suspicious_patterns=result.get("suspicious_patterns", []),
                confidence=result.get("confidence", 0.0),
                recommended_tools=result.get("recommended_tools", []),
            )

        except Exception as e:
            logger.error(f"Image metadata analysis failed: {e}")
            return ImageSteganography(
                image_id="error",
                lsb_anomaly=False,
                metadata_hidden_data=False,
                suspicious_patterns=[],
                confidence=0.0,
                recommended_tools=[],
            )

    def detect_network_steganography(
        self, network_data: Dict[str, Any]
    ) -> SteganographyAnalysis:
        """
        Detect steganography in network traffic

        Args:
            network_data: Network packet data

        Returns:
            SteganographyAnalysis: Detection results
        """
        logger.info("Analyzing network traffic for steganography")

        system_message = """You are a network steganography expert.
Detect covert channels in network traffic:
- Timing channels
- Protocol field manipulation
- Packet size patterns
- DNS tunneling
- ICMP covert channels
- HTTP header manipulation"""

        network_str = "\n".join([f"{k}: {v}" for k, v in network_data.items()])

        prompt = f"""Analyze this network traffic for steganographic covert channels:

Network Data:
{network_str}

Provide analysis in JSON format:
{{
    "hidden_data_detected": boolean,
    "confidence": float (0-1),
    "steganography_type": "timing" | "protocol_field" | "dns_tunnel" | "icmp" | "http_header" | "none",
    "indicators": [list of steganographic indicators],
    "extraction_method": "method to extract hidden data or null",
    "estimated_payload_size": estimated size in bytes or null,
    "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            file_id = f"network_{datetime.now().timestamp()}"

            return SteganographyAnalysis(
                file_id=file_id,
                hidden_data_detected=result.get("hidden_data_detected", False),
                confidence=result.get("confidence", 0.0),
                steganography_type=result.get("steganography_type", "none"),
                indicators=result.get("indicators", []),
                extraction_method=result.get("extraction_method"),
                estimated_payload_size=result.get("estimated_payload_size"),
                risk_level=result.get("risk_level", "LOW"),
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"Network steganography detection failed: {e}")
            return SteganographyAnalysis(
                file_id="error",
                hidden_data_detected=False,
                confidence=0.0,
                steganography_type="error",
                indicators=[],
                extraction_method=None,
                estimated_payload_size=None,
                risk_level="UNKNOWN",
                timestamp=datetime.now().isoformat(),
            )

    def analyze_audio_steganography(
        self, audio_properties: Dict[str, Any]
    ) -> SteganographyAnalysis:
        """
        Detect hidden data in audio files

        Args:
            audio_properties: Audio file properties

        Returns:
            SteganographyAnalysis: Detection results
        """
        logger.info("Analyzing audio for steganography")

        system_message = """You are an audio steganography expert.
Detect hidden information in audio using techniques:
- LSB encoding in audio samples
- Phase encoding
- Echo hiding
- Spread spectrum techniques
- Frequency masking"""

        audio_str = "\n".join([f"{k}: {v}" for k, v in audio_properties.items()])

        prompt = f"""Analyze this audio file for steganographic content:

Audio Properties:
{audio_str}

Provide analysis in JSON format:
{{
    "hidden_data_detected": boolean,
    "confidence": float (0-1),
    "steganography_type": "lsb" | "phase" | "echo" | "spread_spectrum" | "frequency" | "none",
    "indicators": [list of suspicious indicators],
    "extraction_method": "recommended extraction method or null",
    "estimated_payload_size": estimated size in bytes or null,
    "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
}}"""

        try:
            result = self.llm_client.complete_with_json(
                prompt, system_message=system_message
            )

            file_id = f"audio_{datetime.now().timestamp()}"

            return SteganographyAnalysis(
                file_id=file_id,
                hidden_data_detected=result.get("hidden_data_detected", False),
                confidence=result.get("confidence", 0.0),
                steganography_type=result.get("steganography_type", "none"),
                indicators=result.get("indicators", []),
                extraction_method=result.get("extraction_method"),
                estimated_payload_size=result.get("estimated_payload_size"),
                risk_level=result.get("risk_level", "LOW"),
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"Audio steganography detection failed: {e}")
            return SteganographyAnalysis(
                file_id="error",
                hidden_data_detected=False,
                confidence=0.0,
                steganography_type="error",
                indicators=[],
                extraction_method=None,
                estimated_payload_size=None,
                risk_level="UNKNOWN",
                timestamp=datetime.now().isoformat(),
            )

    def _analyze_text_characters(self, text: str) -> str:
        """Analyze text for suspicious characters"""
        stats = {
            "length": len(text),
            "whitespace_count": text.count(" ") + text.count("\t") + text.count("\n"),
            "zero_width_chars": sum(
                1 for c in text if ord(c) in [0x200B, 0x200C, 0x200D, 0xFEFF]
            ),
            "rtl_marks": sum(1 for c in text if ord(c) in [0x202E, 0x202D]),
            "unusual_unicode": sum(1 for c in text if ord(c) > 0x7F),
        }

        return "\n".join([f"{k}: {v}" for k, v in stats.items()])


# Example usage
if __name__ == "__main__":
    stego = SteganographyModule()

    # Test text steganography
    print("=" * 70)
    print("TEXT STEGANOGRAPHY DETECTION")
    print("=" * 70)

    # Example with hidden message in first letters
    hidden_text = """
    Hello there! I hope you are doing well today.
    Delightful weather we're having, isn't it?
    Enjoy your afternoon and stay safe!
    """

    text_result = stego.analyze_text_steganography(hidden_text)
    print(f"Hidden Message Detected: {text_result.hidden_message_detected}")
    print(f"Technique: {text_result.technique}")
    print(f"Confidence: {text_result.confidence:.2f}")
    if text_result.extracted_data:
        print(f"Extracted Data: {text_result.extracted_data}")

    # Test image metadata steganography
    print("\n" + "=" * 70)
    print("IMAGE METADATA STEGANOGRAPHY")
    print("=" * 70)

    image_metadata = {
        "format": "JPEG",
        "width": 1920,
        "height": 1080,
        "exif_comment": base64.b64encode(b"secret_payload").decode(),
        "creation_date": "2025:01:15 14:30:00",
        "camera_model": "Canon EOS",
        "software": "StegTool v2.0",
    }

    image_result = stego.analyze_image_metadata(image_metadata)
    print(f"LSB Anomaly: {image_result.lsb_anomaly}")
    print(f"Metadata Hidden Data: {image_result.metadata_hidden_data}")
    print(f"Confidence: {image_result.confidence:.2f}")
    print(f"Suspicious Patterns: {', '.join(image_result.suspicious_patterns)}")

    # Test network steganography
    print("\n" + "=" * 70)
    print("NETWORK STEGANOGRAPHY DETECTION")
    print("=" * 70)

    network_data = {
        "protocol": "ICMP",
        "packet_count": 1000,
        "payload_size_variance": "high",
        "timing_pattern": "regular intervals",
        "unusual_fields": ["ID field contains non-sequential values"],
    }

    network_result = stego.detect_network_steganography(network_data)
    print(f"Hidden Data Detected: {network_result.hidden_data_detected}")
    print(f"Steganography Type: {network_result.steganography_type}")
    print(f"Confidence: {network_result.confidence:.2f}")
    print(f"Risk Level: {network_result.risk_level}")

    # Test audio steganography
    print("\n" + "=" * 70)
    print("AUDIO STEGANOGRAPHY DETECTION")
    print("=" * 70)

    audio_properties = {
        "format": "WAV",
        "sample_rate": 44100,
        "bit_depth": 16,
        "channels": 2,
        "duration": 180,
        "lsb_entropy": "abnormally high",
        "spectral_anomalies": ["unusual patterns in high frequencies"],
    }

    audio_result = stego.analyze_audio_steganography(audio_properties)
    print(f"Hidden Data Detected: {audio_result.hidden_data_detected}")
    print(f"Steganography Type: {audio_result.steganography_type}")
    print(f"Confidence: {audio_result.confidence:.2f}")
    print(f"Indicators: {', '.join(audio_result.indicators)}")
