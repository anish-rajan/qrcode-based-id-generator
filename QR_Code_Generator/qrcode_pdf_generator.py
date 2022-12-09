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
import csv
from ast import literal_eval
from fpdf import FPDF
import re


def flatten_json(payload):
    final_payload = dict()
    for key in payload:
        if type(payload[key]) is dict:
            temp_payload = flatten_json(payload[key])
            for key in temp_payload:
                final_payload[key] = temp_payload[key]
        else:
            final_payload[key] = payload[key]
    return final_payload


def convert_img_to_pdf(img_file, pdf_name, initial_payload):
    pdf_path = "./Output/{0}".format(pdf_name)
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Times", size=10)
    line_height = pdf.font_size * 2.5
    col_width = pdf.epw / 8  # distribute content evenly
    payload = flatten_json(initial_payload)
    for key in payload:
        if key == "img":
            data = bytes.fromhex(str(payload[key])[2:])
            with open('image.png', 'wb') as file:
                file.write(data)
            pdf.image('image.png', x=100, y=60)
        else:
            pdf.multi_cell(col_width, line_height, key, border=1,
                new_x="RIGHT", new_y="TOP", max_line_height=pdf.font_size)
            pdf.multi_cell(col_width, line_height, payload[key], border=1,
                    new_x="RIGHT", new_y="TOP", max_line_height=pdf.font_size)
            pdf.ln(line_height)
    img = Image.open(img_file).resize((300,300),resample=Image.NEAREST)
    pdf.image(img, x=100, y=80)
    pdf.output(pdf_path)



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
    b64string = "PH1:" + b64string
    qr_code = pyqrcode.create(b64string,error='L')
    qr_code.png('qr_code.png', scale = 6)

def ver0_qr_generator(initial_payload, private_key, signature_mapper, pretty_spaces):
    privKey = ed25519.SigningKey(private_key,encoding='hex')
    payload = initial_payload.copy()
    signature_payload = dict()
    signature_mapper = literal_eval(signature_mapper)
    for item in signature_mapper:
        signature_payload[item] = payload[item] 
    if pretty_spaces!=-1:
        signature_payload = json.dumps(signature_payload, indent=pretty_spaces)
    signature = privKey.sign(bytes(signature_payload, 'utf-8'), encoding='base64')
    signature = str(signature)
    payload["signature"] = signature
    payload = json.dumps(payload)
    qr_code = pyqrcode.create(payload)
    qr_code.png('qr_code.png', scale = 6)

def create_qrs_csv_input(input_path, config_file, ver0_private_key, cwt_private_key):
    n = len(sys.argv)
    if n > 1:
        type_qr_code = sys.argv[1]
    else:
        type_qr_code = "json"
    csv.register_dialect('piper', delimiter='|', quoting=csv.QUOTE_NONE)
    file_obj_config = open(config_file)
    inputs = json.load(file_obj_config)
    configs = dict()
    for type in inputs:
        if type['type'] == 'json':
            configs['json'] = dict()
            configs['json']['payload'] = type['payload']
            configs['json']['signature_mapper'] = type['signature_mapper']
            configs['json']['pretty_spaces'] = type['pretty_spaces']
        elif type['type'] == 'cwt':
            configs['cwt'] = dict()
            configs['cwt']['payload'] = type['payload']

    with open(input_path) as file_obj:

        reader_obj = csv.DictReader(file_obj, dialect='piper')
        for row in reader_obj:
            json_str = replace_variables(configs[type_qr_code]['payload'], row)
            if type_qr_code == 'cwt':
                cwt_qr_generator(json_str, cwt_private_key)
                convert_img_to_pdf("./qr_code.png",row["vid"],json_str)
            elif type_qr_code == 'json':
                ver0_qr_generator(json_str,ver0_private_key,configs['json']['signature_mapper'],configs['json']['pretty_spaces'])
                convert_img_to_pdf("./qr_code.png",row["vid"],json_str)
            
def replace_variables(payload, values):
    final_payload = dict()
    for key in payload:
        if type(payload[key]) is dict:
            final_payload[key] = replace_variables(payload[key],values)
        elif payload[key][0] == '{':
            temp_var = payload[key]
            final_payload[key] = values[temp_var[1:-1]]
        else:
            final_payload[key] = payload[key]
    return final_payload

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
    # cwt_qr_generator(cwt_payload, private_key_file)
    # convert_img_to_pdf("./qr_code.png")
    create_qrs_csv_input("./test-import.csv","config.json",private_key, private_key_file)

    