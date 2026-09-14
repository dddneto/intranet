from setuptools import setup, find_packages

setup(
    name="servidor-assinatura-digital",
    version="1.0.0",
    description="Servidor de Assinatura Digital Local - Conforme Lei 14.063/2020",
    author="Servidor Local",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn[standard]>=0.23.0",
        "cryptography>=41.0.0",
        "python-multipart>=0.0.6",
        "pydantic>=2.0.0",
    ],
    python_requires=">=3.9",
)
