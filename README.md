# Scripts de Auditoría IAM

Scripts de bash para auditar credenciales e identidades administrativas en cuentas AWS.

## Requisitos

- AWS CLI configurado
- jq instalado
- Perfiles SSO autenticados (local) o credenciales por defecto (CloudShell)

## Scripts Disponibles

### 1. audit_iam_credentials.sh

Audita credenciales IAM analizando inactividad, rotación y estado de MFA.

**Uso:**
```bash
./audit_iam_credentials.sh <accounts_file> [days_inactive] [days_rotation] [timezone]
```

**Parámetros:**
- `accounts_file`: Archivo con cuentas (formato: `account_id:profile` o `account_id`)
- `days_inactive`: Días sin actividad (default: 30)
- `days_rotation`: Días sin rotar credenciales (default: 90)
- `timezone`: Zona horaria (default: America/Bogota)

**Ejemplos:**
```bash
# Con defaults
./audit_iam_credentials.sh accounts_iam.txt

# Personalizado
./audit_iam_credentials.sh accounts_iam.txt 60 120 America/New_York
```

**Salida:**
- Archivos CSV: `IAM_cred_reports/credentials_report_account_{últimos4dígitos}_{timestamp}_GMT{offset}.csv`
- Tres tablas en pantalla:
  - Análisis de inactividad
  - Análisis de rotación de credenciales
  - Análisis de MFA

**Lógica:**
- Solo analiza métodos de acceso habilitados
- N/A en last_used = credencial activa nunca usada (hallazgo de seguridad)
- N/A en last_rotated = credencial no existe o inactiva

---

### 2. audit_iam_admin_identities.sh

Detecta usuarios y roles con permisos administrativos.

**Uso:**
```bash
./audit_iam_admin_identities.sh <accounts_file> [timezone]
```

**Parámetros:**
- `accounts_file`: Archivo con cuentas (formato: `account_id:profile` o `account_id`)
- `timezone`: Zona horaria (default: America/Bogota)

**Ejemplos:**
```bash
# Con defaults
./audit_iam_admin_identities.sh accounts_iam.txt

# Con zona horaria personalizada
./audit_iam_admin_identities.sh accounts_iam.txt America/New_York
```

**Salida:**
- Archivo TXT: `IAM_admins_report/iam_admin_identities_{timestamp}_GMT{offset}.txt`
- Tabla en tiempo real con columnas:
  - IDENTITY_ARN
  - POLICY_TYPE (Managed/Inline)
  - POLICY_NAME
  - ASSIGNMENT (Direct/Via Group)

**Criterios de detección:**

**Managed policies:**
- AdministratorAccess
- PowerUserAccess

**Inline policies (mismo Statement):**
- `Action: "*"` + `Resource: "*"` + `Effect: "Allow"` (permisos totales)
- `Action: "iam:*"` + `Resource: "*"` + `Effect: "Allow"` (control total IAM)

**Prevención de falsos positivos:**
- NO detecta: `Action: ["logs:Get*"]` + `Resource: "*"` (solo lectura)
- NO detecta: `Action: ["s3:*"]` + `Resource: "*"` (solo S3)
- SÍ detecta: `Action: "iam:*"` + `Resource: "*"` (puede otorgarse cualquier permiso)

**Análisis:**
- Usuarios: Políticas directas + heredadas por grupos
- Roles: Políticas directas (excluye AWSService*)
- Grupos: Políticas managed e inline

---

## Formato de Archivo de Cuentas

**Local (con perfiles SSO):**
```
111111111111:Perfil_Cuenta_1111
222222222222:Perfil_Cuenta_Security_2222
```

**CloudShell (sin perfiles):**
```
111111111111
222222222222
```

## Autenticación SSO

Los scripts validan autenticación antes de ejecutar. Si un perfil no está autenticado:

```bash
aws sso login --profile <profile_name>
```

## Directorios de Salida

- `IAM_cred_reports/`: Reportes de credenciales (CSV)
- `IAM_admins_report/`: Reportes de identidades administrativas (TXT)

## Notas

- Ambos scripts funcionan en local y CloudShell
- Salida en tiempo real durante ejecución
- Archivos con timestamp y offset GMT
- Excluye cuenta root de análisis
- Excluye roles de servicio AWS (AWSService*)
