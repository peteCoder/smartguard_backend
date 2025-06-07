import qrcode

# Data you want the QR code to contain
data = "https://twitter.com"

# Generate QR code
qr = qrcode.QRCode(
    version=1,  # controls size (1-40), higher is bigger
    error_correction=qrcode.constants.ERROR_CORRECT_L,  # L=Low error correction
    box_size=10,  # size of each box
    border=4,  # thickness of the border
)
qr.add_data(data)
qr.make(fit=True)

# Create an image
img = qr.make_image(fill_color="black", back_color="white")

# Save the QR code image
img.save("twitter_qr.png")


