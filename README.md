# CJISSECPOL - Prioritizing the upcoming NIST800-53 requirements.
Upcoming CJISSECPOL policies are mapped to NIST800-53 policies. This script helps prioritize. 

## Prepping the environment
The **config.yaml** file contains options for deciding:
- Where your files are loaded from.
- Where results are saved.
- If you want additional details in the output. 

Always good to setup a virtual environment <3
```
cd path\to\project
python -m venv my_env
.\my_env\scripts\[pick_activation_script]
```

## Example Usage
The script expects that your **config.yaml** will be in your current directory.
If you would prefer to specify its location, you can specify the path in the `main()` function in the `__main__.py` file.

Running the script:
```
python .\code\__main__.py
```

# Note 
The following NIST controls are not available in the MITRE top-attack-techniques priority calculator (05/04/2023)
- AC-11: Session Lock
- AC-14: Permitted Actions Without Identification Or Authentication
- IR-5: Incident Monitoring

# External Mappings & Prioritization References
https://top-attack-techniques.mitre-engenuity.org/calculator

https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/releases/download/v1.5.0/attack-10.1-nist800-53-r5-mappings.xlsx

https://www.cisecurity.org/insights/white-papers/cis-controls-v8-mapping-to-nist-800-53-rev-5
