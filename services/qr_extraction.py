from PIL import Image
import io
from pyzbar.pyzbar import decode
from fastapi import UploadFile
from typing import Optional
from fastapi import UploadFile
import cv2
import numpy as np

def extract_qr_code(file: UploadFile) -> Optional[str]:
    try:
        # Read the file as bytes
        image_bytes = file.file.read()

        # Convert bytes to numpy array
        npimg = np.frombuffer(image_bytes, np.uint8)

        # Decode the image (irrespective of file type)
        img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

        # Initialize QRCode detector
        detector = cv2.QRCodeDetector()

        # Detect and decode
        data, bbox, _ = detector.detectAndDecode(img)
        
        if bbox is not None and data:
            return data
        else:
            return None

    except Exception as e:
        print("Error extracting QR code:", e)
        return None


