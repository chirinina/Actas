from flask import Flask, render_template, request, send_file
from docx import Document
import random

app = Flask(__name__)

def reemplazar_texto_con_formato(doc, campos):
    for p in doc.paragraphs:
        for run in p.runs:
            for k, v in campos.items():
                if k in run.text:
                    run.text = run.text.replace(k, v)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    for run in p.runs:
                        for k, v in campos.items():
                            if k in run.text:
                                run.text = run.text.replace(k, v)

@app.route('/')
def index():
    valores_aleatorios = {}

    for i in range(1, 10):
        if i in [3, 6]:
            valor = random.randint(10, 15)
        else:
            valor = random.randint(4, 9)
        valores_aleatorios[f'ITEM{i}_NUMERAL'] = str(valor)

    total = sum(int(v) for v in valores_aleatorios.values())
    valores_aleatorios['TOTAL_NUMERAL'] = str(total)

    return render_template('form.html', valores=valores_aleatorios)

@app.route('/generar', methods=['POST'])
def generar():
    campos = {f"{{{{{k}}}}}": v for k, v in request.form.items()}
    plantilla = "plantilla_acta.docx"
    doc = Document(plantilla)

    reemplazar_texto_con_formato(doc, campos)

    postulante = request.form.get("POSTULANTE", "documento").replace(" ", "_")
    filename = f"{postulante}.docx"
    doc.save(filename)
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
