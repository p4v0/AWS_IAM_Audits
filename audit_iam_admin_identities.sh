#!/bin/bash
#
# Script de auditoría de identidades IAM con permisos administrativos
#
# Detecta usuarios y roles con permisos administrativos mediante:
# - Políticas managed: AdministratorAccess, PowerUserAccess
# - Políticas inline con permisos administrativos (en el mismo Statement):
#   * Action:* AND Resource:* AND Effect:Allow (permisos totales)
#   * Action:iam:* AND Resource:* AND Effect:Allow (control total de IAM)
# - Permisos heredados por grupos (para usuarios)
#
# Requisitos:
#   - AWS CLI configurado
#   - jq instalado
#   - Perfiles SSO autenticados (local) o credenciales por defecto (CloudShell)
#
# Uso:
#   ./audit_iam_admin_identities.sh <accounts_file> [timezone]
#
# Parámetros:
#   accounts_file: Archivo con formato account_id:profile (local) o account_id (CloudShell)
#   timezone:      Zona horaria para timestamp (default: America/Bogota)
#
# Ejemplos:
#   # Con defaults
#   ./audit_iam_admin_identities.sh accounts_iam.txt
#
#   # Con zona horaria personalizada
#   ./audit_iam_admin_identities.sh accounts_iam.txt America/New_York
#
#   # En CloudShell (sin perfiles en archivo)
#   ./audit_iam_admin_identities.sh accounts_cloudshell.txt
#
# Formato archivo de cuentas:
#   Local:      account_id:profile_name (uno por línea)
#   CloudShell: account_id (uno por línea)
#
# Salida:
#   - Archivo TXT: iam_admin_identities_{YYYYMMDD_HHMMSS}_GMT{offset}.txt
#   - Tabla en tiempo real con columnas:
#     * IDENTITY_ARN: ARN del usuario o rol
#     * POLICY_TYPE: Managed o Inline
#     * POLICY_NAME: Nombre de la política
#     * ASSIGNMENT: Direct o Via Group: {nombre_grupo}
#
# Lógica de detección inline policies:
#   Valida con jq que en el MISMO Statement existan:
#   - Effect == "Allow"
#   - Action == "*" o Action array contenga "*" o "iam:*"
#   - Resource == "*" o Resource array contenga "*"
#
# Criterios de permisos administrativos:
#   - Action:* = Permisos totales sobre todos los servicios
#   - Action:iam:* = Control total de IAM (puede otorgarse cualquier permiso)
#   - Ambos con Resource:* y Effect:Allow se consideran administrativos
#
# Prevención de falsos positivos:
#   - NO detecta políticas con Resource:* si Action no es wildcard administrativo
#   - Ejemplo NO detectado: Action:["logs:Get*","cloudwatch:Describe*"] + Resource:"*"
#   - Ejemplo NO detectado: Action:["s3:*"] + Resource:"*" (solo S3, no administrativo)
#   - Solo detecta: Action:"*" o Action:"iam:*" con Resource:"*" y Effect:"Allow"
#
# Análisis por tipo de identidad:
#   - Usuarios: Políticas directas + heredadas por grupos
#   - Roles: Solo políticas directas (excluye roles AWSService*)
#   - Grupos: Políticas managed e inline del grupo
#
# Notas:
#   - Excluye roles que inician con "AWSService" (roles de servicio AWS)
#   - Salida en tiempo real conforme detecta cada identidad administrativa
#   - Validación de autenticación SSO antes de iniciar análisis
#

set -e

ACCOUNTS_FILE="${1:-accounts_iam.txt}"
TIMEZONE="${2:-America/Bogota}"
OUTPUT_DIR="IAM_admins_report"

mkdir -p "$OUTPUT_DIR"

if [ ! -f "$ACCOUNTS_FILE" ]; then
  echo "Error: Archivo $ACCOUNTS_FILE no encontrado"
  echo "Uso: $0 <archivo_cuentas> [timezone]"
  exit 1
fi

TIMESTAMP=$(TZ="$TIMEZONE" date '+%Y%m%d_%H%M%S')
GMT_OFFSET=$(TZ="$TIMEZONE" date '+%z' | sed 's/\([+-]\)\([0-9][0-9]\)\([0-9][0-9]\)/\1\2/')
OUTPUT_FILE="$OUTPUT_DIR/iam_admin_identities_${TIMESTAMP}_GMT${GMT_OFFSET}.txt"
TEMP_RESULTS=$(mktemp)

validate_profile() {
  local profile=$1
  aws sts get-caller-identity --profile "$profile" >/dev/null 2>&1
}

check_inline_policy() {
  local policy_doc=$1
  echo "$policy_doc" | jq -e '
    .Statement[] | 
    select(
      .Effect == "Allow" and
      (
        (.Action == "*") or 
        (.Action | type == "array" and any(. == "*" or . == "iam:*"))
      ) and
      (
        (.Resource == "*") or 
        (.Resource | type == "array" and any(. == "*"))
      )
    )
  ' >/dev/null 2>&1
}

echo "=== AUDITORÍA IAM - IDENTIDADES ADMINISTRATIVAS ==="
echo "Fecha: $(TZ="$TIMEZONE" date '+%Y-%m-%d %H:%M:%S') (GMT$GMT_OFFSET)"
echo ""

echo "Validando perfiles..."
INVALID_PROFILES=()
while IFS=':' read -r ACCOUNT_ID PROFILE || [ -n "$ACCOUNT_ID" ]; do
  [ -z "$ACCOUNT_ID" ] || [[ "$ACCOUNT_ID" =~ ^# ]] && continue
  ACCOUNT_ID=$(echo "$ACCOUNT_ID" | xargs)
  PROFILE=$(echo "$PROFILE" | xargs)
  
  if [ -n "$PROFILE" ]; then
    if ! validate_profile "$PROFILE"; then
      INVALID_PROFILES+=("$ACCOUNT_ID:$PROFILE")
    fi
  fi
done < "$ACCOUNTS_FILE"

if [ ${#INVALID_PROFILES[@]} -gt 0 ]; then
  echo "Error: Perfiles sin autenticar:"
  for item in "${INVALID_PROFILES[@]}"; do
    echo "  - $item"
  done
  exit 1
fi

echo "Perfiles validados"
echo ""
echo "=== IDENTIDADES ADMINISTRATIVAS (en tiempo real) ==="
echo ""
(echo -e "IDENTITY_ARN\tPOLICY_TYPE\tPOLICY_NAME\tASSIGNMENT") | column -t -s $'\t'
echo ""

while IFS=':' read -r ACCOUNT_ID PROFILE || [ -n "$ACCOUNT_ID" ]; do
  [ -z "$ACCOUNT_ID" ] || [[ "$ACCOUNT_ID" =~ ^# ]] && continue
  ACCOUNT_ID=$(echo "$ACCOUNT_ID" | xargs)
  PROFILE=$(echo "$PROFILE" | xargs)
  
  [ -n "$PROFILE" ] && PROFILE_ARG="--profile $PROFILE" || PROFILE_ARG=""
  
  aws iam list-users $PROFILE_ARG --output json 2>/dev/null | jq -r '.Users[].UserName' | while read USER; do
    USER_ARN="arn:aws:iam::${ACCOUNT_ID}:user/${USER}"
    
    aws iam list-attached-user-policies --user-name "$USER" $PROFILE_ARG --output json 2>/dev/null | \
      jq -r '.AttachedPolicies[] | select(.PolicyArn | contains("AdministratorAccess") or contains("PowerUserAccess")) | .PolicyName' | while read POLICY; do
        echo -e "${USER_ARN}\tManaged\t${POLICY}\tDirect" | tee -a "$TEMP_RESULTS" | column -t -s $'\t'
      done
    
    aws iam list-user-policies --user-name "$USER" $PROFILE_ARG --output json 2>/dev/null | jq -r '.PolicyNames[]' | while read POLICY; do
        POLICY_DOC=$(aws iam get-user-policy --user-name "$USER" --policy-name "$POLICY" $PROFILE_ARG --output json 2>/dev/null | jq -c '.PolicyDocument')
        if check_inline_policy "$POLICY_DOC"; then
          echo -e "${USER_ARN}\tInline\t${POLICY}\tDirect" | tee -a "$TEMP_RESULTS" | column -t -s $'\t'
        fi
      done
    
    aws iam list-groups-for-user --user-name "$USER" $PROFILE_ARG --output json 2>/dev/null | jq -r '.Groups[].GroupName' | while read GROUP; do
        aws iam list-attached-group-policies --group-name "$GROUP" $PROFILE_ARG --output json 2>/dev/null | \
          jq -r '.AttachedPolicies[] | select(.PolicyArn | contains("AdministratorAccess") or contains("PowerUserAccess")) | .PolicyName' | while read POLICY; do
            echo -e "${USER_ARN}\tManaged\t${POLICY}\tVia Group: ${GROUP}" | tee -a "$TEMP_RESULTS" | column -t -s $'\t'
          done
        
        aws iam list-group-policies --group-name "$GROUP" $PROFILE_ARG --output json 2>/dev/null | jq -r '.PolicyNames[]' | while read POLICY; do
            POLICY_DOC=$(aws iam get-group-policy --group-name "$GROUP" --policy-name "$POLICY" $PROFILE_ARG --output json 2>/dev/null | jq -c '.PolicyDocument')
            if check_inline_policy "$POLICY_DOC"; then
              echo -e "${USER_ARN}\tInline\t${POLICY}\tVia Group: ${GROUP}" | tee -a "$TEMP_RESULTS" | column -t -s $'\t'
            fi
          done
      done
  done
  
  aws iam list-roles $PROFILE_ARG --output json 2>/dev/null | jq -r '.Roles[] | select(.RoleName | startswith("AWSService") | not) | .RoleName' | while read ROLE; do
    ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE}"
    
    aws iam list-attached-role-policies --role-name "$ROLE" $PROFILE_ARG --output json 2>/dev/null | \
      jq -r '.AttachedPolicies[] | select(.PolicyArn | contains("AdministratorAccess") or contains("PowerUserAccess")) | .PolicyName' | while read POLICY; do
        echo -e "${ROLE_ARN}\tManaged\t${POLICY}\tDirect" | tee -a "$TEMP_RESULTS" | column -t -s $'\t'
      done
    
    aws iam list-role-policies --role-name "$ROLE" $PROFILE_ARG --output json 2>/dev/null | jq -r '.PolicyNames[]' | while read POLICY; do
        POLICY_DOC=$(aws iam get-role-policy --role-name "$ROLE" --policy-name "$POLICY" $PROFILE_ARG --output json 2>/dev/null | jq -c '.PolicyDocument')
        if check_inline_policy "$POLICY_DOC"; then
          echo -e "${ROLE_ARN}\tInline\t${POLICY}\tDirect" | tee -a "$TEMP_RESULTS" | column -t -s $'\t'
        fi
      done
  done
  
done < "$ACCOUNTS_FILE"

echo ""

if [ -s "$TEMP_RESULTS" ]; then
    (echo -e "IDENTITY_ARN\tPOLICY_TYPE\tPOLICY_NAME\tASSIGNMENT";
    cat "$TEMP_RESULTS") | column -t -s $'\t' > "$OUTPUT_FILE"
else
    echo "No se encontraron identidades administrativas" | tee "$OUTPUT_FILE"
fi

rm -f "$TEMP_RESULTS"

echo ""
echo "=== FIN AUDITORÍA ==="
echo "Reporte guardado en: $OUTPUT_FILE"
