import math
import os
from collections import Counter

EXECUTABLE_EXTENSIONS = {'.exe', '.dll', '.scr', '.com', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.elf', '.sh'}
SUSPICIOUS_SCRIPT_MARKERS = [
    b'powershell -enc', b'powershell.exe -enc', b'frombase64string',
    b'cmd.exe /c', b'wscript.shell', b'regsvr32', b'rundll32', b'certutil',
]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def extract_features(filepath: str) -> dict:
    """Extract the project's eight behavioural features plus scan metadata.

    A browser upload is a static scan, so activity counters describe the
    controlled upload transaction itself. They are NOT claimed to be the
    activity of an unknown process. Real process-attributed counters belong
    to the live watchdog monitor planned for the behaviour-monitor page.
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    name = os.path.basename(filepath)
    ext = os.path.splitext(name)[1].lower()
    entropy = shannon_entropy(data)

    features = {
        'write_count': 1,
        'delete_count': 0,
        'create_count': 1,
        'rename_count': 0,
        'write_entropy': round(entropy, 4),
        'ext_diversity': 1,
        'sensitive_path_access': 0,
        'read_write_ratio': 1.0,
        'hidden_file_activity': 1 if name.startswith('.') else 0,
        'execution_attempts': 1 if ext in EXECUTABLE_EXTENSIONS else 0,
    }

    lower = data[:5_000_000].lower()
    pe_or_elf = data.startswith(b'MZ') or data.startswith(b'\x7fELF')
    script_marker = any(marker in lower for marker in SUSPICIOUS_SCRIPT_MARKERS)

    # Conservative static risk score. This is deliberately not presented as
    # a validated ML probability.
    score = 0
    reasons = []
    if script_marker:
        score += 55
        reasons.append('suspicious command/script marker')
    if pe_or_elf and ext in EXECUTABLE_EXTENSIONS:
        score += 25
        reasons.append('executable binary format')
    if ext in EXECUTABLE_EXTENSIONS:
        score += 10
        reasons.append('executable/script extension')
    if entropy >= 7.6 and ext in EXECUTABLE_EXTENSIONS:
        score += 20
        reasons.append('very high entropy in executable/script')

    score = min(score, 100)
    if score >= 70:
        prediction, risk = 'Malware', 'HIGH'
    elif score >= 40:
        prediction, risk = 'Suspicious', 'MEDIUM'
    else:
        prediction, risk = 'Safe', 'LOW'

    confidence = max(55.0, min(99.0, 50.0 + abs(score - 50) * 0.98))
    if prediction == 'Safe':
        confidence = max(55.0, min(99.0, 100.0 - score * 0.6))

    features.update({
        'prediction': prediction,
        'risk': risk,
        'confidence': round(confidence, 2),
        'score': score,
        'reasons': reasons or ['no strong static indicators detected'],
        'file_size': os.path.getsize(filepath),
        'extension': ext or 'none',
    })
    return features
