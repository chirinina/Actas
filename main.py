from flask import Flask, render_template, request, send_file
from docx import Document
import io
import random

app = Flask(__name__)

def reemplazar_en_runs(parrafos, campos):
    for parrafo in parrafos:
        texto_total = "".join(run.text for run in parrafo.runs)
        for clave, valor in campos.items():
            if clave in texto_total:
                texto_total = texto_total.replace(clave, valor)

        if texto_total != "".join(run.text for run in parrafo.runs):
            for i in range(len(parrafo.runs)):
                parrafo.runs[i].text = ""
            parrafo.runs[0].text = texto_total

def reemplazar_en_documento(doc, campos):
    reemplazar_en_runs(doc.paragraphs, campos)
    for tabla in doc.tables:
        for fila in tabla.rows:
            for celda in fila.cells:
                reemplazar_en_runs(celda.paragraphs, campos)

@app.route('/')
def index():
    valores = {}
    for i in range(1, 10):
        if i in [3, 6]:
            valores[f"ITEM{i}_NUMERAL"] = str(random.randint(10, 15))
        else:
            valores[f"ITEM{i}_NUMERAL"] = str(random.randint(4, 9))

    total = sum(int(val) for val in valores.values())
    valores["TOTAL_NUMERAL"] = str(total)
    return render_template("form.html", valores=valores)

@app.route('/generar', methods=['POST'])
def generar():
    campos = {f"{{{{{clave}}}}}": valor for clave, valor in request.form.items()}
    doc = Document("plantilla_acta.docx")
    reemplazar_en_documento(doc, campos)

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)

    filename = f"{request.form.get('POSTULANTE', 'documento')}.docx"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )

if __name__ == '__main__':
    app.run(debug=True)
