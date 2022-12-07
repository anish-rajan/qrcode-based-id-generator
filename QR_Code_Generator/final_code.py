import cwt
from cwt import COSEKey
from cwt import Claims
import ed25519
import sys
import pyqrcode
import codecs
import img2pdf
from PIL import Image
import os
import json

def convert_img_to_pdf(img_file, pdf_name):
    pdf_path = "./Output/{0}".format(pdf_name)
    image = Image.open(img_file)
    pdf_bytes = img2pdf.convert(image.filename)
    file = open(pdf_path, "wb")
    file.write(pdf_bytes)
    image.close()
    file.close()



def cwt_qr_generator(payload, private_key_file):
    with open(private_key_file) as key_file:
        private_key = COSEKey.from_pem(key_file.read(), alg=-8, kid="01")
    token = cwt.encode(
        {
            1: "PH",  # iss
            8: { 3: b'Key'},
        169: payload,
        },
        private_key,
    )
    b64string = codecs.encode(codecs.decode(token.hex(), 'hex'), 'base64').decode()
    qr_code = pyqrcode.create(b64string,error='L')
    qr_code.png('qr_code.png', scale = 6)

def ver0_qr_generator(payload, private_key):
    privKey = ed25519.SigningKey(private_key,encoding='hex')
    payload = str(payload)
    signature = privKey.sign(bytes(payload, 'utf-8'), encoding='hex')
    qr_code = pyqrcode.create(signature)
    qr_code.png('qr_code.png', scale = 6)


def create_qrs(inputs_path, ver0_private_key, cwt_private_key):
    file_obj = open(inputs_path)
    inputs = json.load(file_obj)
    count = 0
    for person in inputs:
        count+=1
        if person['type'] == 'cwt':
            cwt_qr_generator(person['payload'], cwt_private_key)
            convert_img_to_pdf("./qr_code.png",count)
        elif person['type'] == 'ver0':
            ver0_qr_generator(person['payload'], ver0_private_key)
            convert_img_to_pdf("./qr_code.png",count)
        else:
            continue



if __name__ == '__main__':
    private_key = b'e21ffeb4072328eddaa435d5a5920422af7dfe7b76fece04391f172b1131b2db'
    private_key_file = "./private_key.pem"
    cwt_payload = {
            "i":"PSA",
            "d":"2022-09-6",
            "img":"h""52494646B00100005745425056503820A4010000300B009D012A2D003A003F1178B3532C2724A2AD566A4980220969001363CDFDAEB264156FA14EADD91927F3FBF5CA5ED9A12C659102FD59D969F22C09B013A25F52A3D0513DB76FE9E11C9E135B0D37A6BE47884C245EDA9926490AA765A58D120000FC3B347BD1DD693DF3E7D53F9D1A0C91834889DF8C8CBD92EEBA140417033DB23E928F4F38AF5C0576F768C2AFC25D439FFBBC2E39C9B9AFE4CD8F24606155412702532C45D15D5357329A4792BA4DB8346114C087E046FD9DBEE82EB36648CDB32ACDD14F946F56F67563D363A7E953C461015DB97268971707ABD6D5B8A5AE8C5D273A1A88AAE3CA55F4061D701AB939C3825FEB4972AFA65A593277165D30FD3DFA4CA83DF998CCDF806D5420550ED57BE6F865BBE8FFF2F93174B258C4B76BB0CC144A2793C12F94869BD2079463172B7ABE08035C0882F6F7124F825A45550005D1BD2C992821CB820FE8032764609BAF9F8B0029162C97B9F6BAF67036137B7587B100B83CAFF227807E49E883894E9459A400D5164C61D87DCCE1508F3E9A1C9D4C4785F37FE8999799B62E7FE6B1C7E06B7C3AACA19C70E840B0000000",
            "sb":{
                "s":"Male",
                "PCN":"1484187209471956",
                "ln":"Mercado Y Realonda",
                "POB":"CITY OF MARIKINA, NCR, CITY OF MANILA, FIRST DISTRICT",
                "sf":"Sophomore",
                "DOB":"1990-05-27",
                "fn":"Arnold Chezella Paulina",
                "mn":"Oninco",
                "BF":"[1,2]"
            }
        }
    # cwt_qr_generator(cwt_payload, private_key_file)
    # convert_img_to_pdf("./qr_code.png")
    create_qrs("./input.json",private_key, private_key_file)

    