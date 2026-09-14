#!/usr/bin/env python3
"""
extract_holerites.py — Extrai nome do funcionário e CNPJ de cada página de um PDF de holerites.
Uso: python3 extract_holerites.py <caminho_do_pdf>
Saída: JSON com lista de páginas e dados extraídos.
"""
import sys
import re
import json

def normalize(s):
    """Remove acentos e normaliza para comparação."""
    import unicodedata
    return unicodedata.normalize('NFD', s).encode('ascii', 'ignore').decode().upper().strip()

def extract_info(text):
    """Extrai nome do funcionário e CNPJ do texto de uma página de holerite."""
    name = None
    cnpj = None

    # Padrão principal: "Filial 1 <código> NOME SOBRENOME <CBO> 1"
    m = re.search(
        r'Filial\s+1\s+\d+\s+([A-ZÁÉÍÓÚÀÃÕÇÊÂ][A-ZÁÉÍÓÚÀÃÕÇÊÂ\s]+?)\s+\d{5,6}\s+1\b',
        text
    )
    if m:
        name = re.sub(r'\s+', ' ', m.group(1)).strip()

    # Padrão secundário: código numérico + NOME + CBO de 5-6 dígitos
    if not name:
        m = re.search(
            r'\b(\d{1,3})\s+([A-ZÁÉÍÓÚÀÃÕÇÊÂ][A-ZÁÉÍÓÚÀÃÕÇÊÂ\s]{4,60}?)\s+\d{5,6}\b',
            text
        )
        if m:
            name = re.sub(r'\s+', ' ', m.group(2)).strip()

    # CNPJ
    m = re.search(r'(\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2})', text)
    if m:
        cnpj = m.group(1)

    return name, cnpj

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Caminho do PDF não informado"}))
        sys.exit(1)

    pdf_path = sys.argv[1]

    try:
        import pdfplumber
    except ImportError:
        print(json.dumps({"error": "pdfplumber não instalado. Execute: pip install pdfplumber"}))
        sys.exit(1)

    results = []
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for i, page in enumerate(pdf.pages):
                text = page.extract_text() or ''
                name, cnpj = extract_info(text)
                results.append({
                    "page":  i + 1,
                    "name":  name,
                    "cnpj":  cnpj,
                    "text_sample": text[:200].replace('\n', ' ')
                })
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    print(json.dumps({"pages": results}))

if __name__ == '__main__':
    main()
