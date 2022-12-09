## How to run The Code

* Run qrcode_pdf_generator.py with two inputs.
    * a csv file having records of people
    * a json config file having configuration information.
* An example has been provided with test-import.csv and config.json.
* Run the code as
```
python3 qrcode_pdf_generator.py
```
A command line argument can also be specified about what config is required. This can be cwt or json
```
python3 qrcode_pdf_generator.py cwt
```
or
```
python3 qrcode_pdf_generator.py cwt
```
There should be an output folder called Output created. This is where the PDF ID Cards are created with all info and QR Code.
