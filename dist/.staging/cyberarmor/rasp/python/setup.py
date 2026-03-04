from setuptools import setup
setup(
    name="aishields-rasp",
    version="1.0.0",
    py_modules=["aishields_rasp"],
    python_requires=">=3.9",
    description="CyberArmor.ai RASP - Runtime Application Self-Protection for AI/LLM APIs",
    author="CyberArmor.ai",
    install_requires=["httpx>=0.25.0"],
    extras_require={"requests": ["requests>=2.28.0"], "aiohttp": ["aiohttp>=3.8.0"]},
    classifiers=["Development Status :: 4 - Beta", "Topic :: Security"],
)
