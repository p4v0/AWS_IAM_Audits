#!/bin/bash
#
# Script de auditoría de credenciales IAM
#
# Descarga el credentials report de IAM para cada cuenta y analiza:
# - Inactividad de usuarios (consola y access keys)
# - Rotación de credenciales (passwords, access keys y certificados)
# - Estado de MFA para acceso por consola
#
# Requisitos:
#   - AWS CLI configurado
#   - Perfiles SSO autenticados (local) o credenciales por defecto (CloudShell)
#
# Uso:
#   ./audit_iam_credentials.sh <accounts_file> [days_inactive] [days_rotation] [timezone]
#
# Parámetros:
#   accounts_file:  Archivo con formato account_id:profile (local) o account_id (CloudShell)
#   days_inactive:  Días sin actividad para considerar inactivo (default: 30)
#   days_rotation:  Días sin rotar credenciales (default: 90)
#   timezone:       Zona horaria para timestamp (default: America/Bogota)
#
# Ejemplos:
#   # Con defaults (30 días inactividad, 90 días rotación)
#   ./audit_iam_credentials.sh accounts_iam.txt
#
#   # Personalizado
#   ./audit_iam_credentials.sh accounts_iam.txt 60 120
#
#   # Con zona horaria
#   ./audit_iam_credentials.sh accounts_iam.txt 30 90 America/New_York
#
#   # En CloudShell (sin perfiles en archivo)
#   ./audit_iam_credentials.sh accounts_cloudshell.txt 30 90
#
# Formato archivo de cuentas:
#   Local:      account_id:profile_name (uno por línea)
#   CloudShell: account_id (uno por línea)
#
# Salida:
#   - Archivos CSV: credentials_report_account_{últimos4dígitos}_{YYYYMMDD_HHMMSS}_GMT{offset}.csv
#   - Tres tablas de análisis en pantalla:
#     1. ANÁLISIS DE INACTIVIDAD: Usuarios sin actividad en consola o access keys
#     2. ANÁLISIS DE ROTACIÓN: Credenciales sin rotar (passwords, keys, certificados)
#     3. ANÁLISIS MFA: Estado de MFA para usuarios con acceso por consola
#
# Lógica de análisis:
#   - Solo analiza métodos de acceso habilitados (password_enabled, access_key_active, cert_active)
#   - Usuarios sin ningún método de acceso activo NO se analizan ni aparecen en los reportes
#   - Inactividad: Muestra usuario si CUALQUIER método habilitado está inactivo
#   - Rotación: Muestra usuario si CUALQUIER credencial habilitada no se ha rotado
#   - MFA: Muestra todos los usuarios con acceso por consola habilitado
#
# Interpretación de N/A en los resultados:
#   - N/A en last_used: Método de acceso activo pero NUNCA usado (hallazgo de seguridad válido)
#   - N/A en last_rotated: Credencial NO existe o no está activa
#   - Ejemplo: access_key_active=true + last_used=N/A = Key activa sin uso (debe revisarse)
#

set -e

ACCOUNTS_FILE="${1:-accounts_iam.txt}"
DAYS_INACTIVE="${2:-30}"
DAYS_ROTATION="${3:-90}"
TIMEZONE="${4:-America/Bogota}"
OUTPUT_DIR="IAM_cred_reports"

mkdir -p "$OUTPUT_DIR"

if [ ! -f "$ACCOUNTS_FILE" ]; then
    echo "Error: Archivo $ACCOUNTS_FILE no encontrado"
    echo "Uso: $0 <accounts_file> [days_inactive] [days_rotation] [timezone]"
    exit 1
fi

TIMESTAMP=$(TZ="$TIMEZONE" date '+%Y%m%d_%H%M%S')
GMT_OFFSET=$(TZ="$TIMEZONE" date '+%z' | sed 's/\([+-]\)\([0-9][0-9]\)\([0-9][0-9]\)/\1\2/')

echo "=== Auditoría de Credenciales IAM ==="
echo "Archivo de cuentas: $ACCOUNTS_FILE"
echo "Días de inactividad: $DAYS_INACTIVE"
echo "Días sin rotación: $DAYS_ROTATION"
echo "Zona horaria: $TIMEZONE (GMT$GMT_OFFSET)"
echo "Fecha: $(TZ="$TIMEZONE" date '+%Y-%m-%d %H:%M:%S')"
echo ""

CUTOFF_INACTIVE=$(date -u -d "$DAYS_INACTIVE days ago" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || date -u -v-${DAYS_INACTIVE}d '+%Y-%m-%dT%H:%M:%S')
CUTOFF_ROTATION=$(date -u -d "$DAYS_ROTATION days ago" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null || date -u -v-${DAYS_ROTATION}d '+%Y-%m-%dT%H:%M:%S')

TEMP_INACTIVITY=$(mktemp)
TEMP_ROTATION=$(mktemp)
TEMP_MFA=$(mktemp)

while IFS=':' read -r ACCOUNT_ID PROFILE || [ -n "$ACCOUNT_ID" ]; do
    [ -z "$ACCOUNT_ID" ] || [[ "$ACCOUNT_ID" =~ ^# ]] && continue
    
    ACCOUNT_ID=$(echo "$ACCOUNT_ID" | xargs)
    PROFILE=$(echo "$PROFILE" | xargs)
    LAST_4="${ACCOUNT_ID: -4}"
    REPORT_FILE="$OUTPUT_DIR/credentials_report_account_${LAST_4}_${TIMESTAMP}_GMT${GMT_OFFSET}.csv"
    
    echo "Procesando cuenta $ACCOUNT_ID..."
    
    if [ -n "$PROFILE" ]; then
        PROFILE_ARG="--profile $PROFILE"
        echo "  Usando perfil: $PROFILE"
    else
        PROFILE_ARG=""
        echo "  Usando credenciales por defecto (CloudShell)"
    fi
    
    # echo "  Generando credentials report..."
    aws iam generate-credential-report $PROFILE_ARG > /dev/null 2>&1 || true
    sleep 3
    
    echo "  Descargando credentials report..."
    aws iam get-credential-report $PROFILE_ARG --query 'Content' --output text 2>/dev/null | base64 -d > "$REPORT_FILE"
    
    if [ ! -f "$REPORT_FILE" ]; then
        echo "  Error: No se pudo descargar el reporte"
        continue
    fi
    
    echo "  Reporte guardado: $REPORT_FILE"
    
    tail -n +2 "$REPORT_FILE" | while IFS=',' read -r user arn creation pwd_enabled pwd_last_used pwd_last_changed pwd_next_rotation mfa_active ak1_active ak1_last_rotated ak1_last_used_date ak1_last_used_region ak1_last_used_service ak2_active ak2_last_rotated ak2_last_used_date ak2_last_used_region ak2_last_used_service cert1_active cert1_last_rotated cert2_active cert2_last_rotated; do
        [ "$user" = "<root_account>" ] && continue
        
        # ANÁLISIS DE INACTIVIDAD
        console_inactive=false
        ak1_inactive=false
        ak2_inactive=false
        
        if [ "$pwd_enabled" = "true" ]; then
            if [ "$pwd_last_used" = "N/A" ] || [ "$pwd_last_used" = "no_information" ] || [[ "$pwd_last_used" < "$CUTOFF_INACTIVE" ]]; then
                console_inactive=true
            fi
        fi
        
        if [ "$ak1_active" = "true" ]; then
            if [ "$ak1_last_used_date" = "N/A" ] || [ "$ak1_last_used_date" = "no_information" ] || [[ "$ak1_last_used_date" < "$CUTOFF_INACTIVE" ]]; then
                ak1_inactive=true
            fi
        fi
        
        if [ "$ak2_active" = "true" ]; then
            if [ "$ak2_last_used_date" = "N/A" ] || [ "$ak2_last_used_date" = "no_information" ] || [[ "$ak2_last_used_date" < "$CUTOFF_INACTIVE" ]]; then
                ak2_inactive=true
            fi
        fi
        
        if [ "$console_inactive" = true ] || [ "$ak1_inactive" = true ] || [ "$ak2_inactive" = true ]; then
            console_display="${pwd_last_used:-N/A}"
            ak1_display="${ak1_last_used_date:-N/A}"
            ak2_display="${ak2_last_used_date:-N/A}"
            
            echo -e "${arn}\t${console_display}\t${ak1_display}\t${ak2_display}" >> "$TEMP_INACTIVITY"
        fi
        
        # ANÁLISIS DE ROTACIÓN DE CREDENCIALES
        pwd_rotated=false
        ak1_rotated=false
        ak2_rotated=false
        cert1_rotated=false
        cert2_rotated=false
        
        if [ "$pwd_enabled" = "true" ]; then
            if [ "$pwd_last_changed" != "N/A" ] && [ "$pwd_last_changed" != "no_information" ] && [[ "$pwd_last_changed" < "$CUTOFF_ROTATION" ]]; then
                pwd_rotated=true
            fi
        fi
        
        if [ "$ak1_active" = "true" ]; then
            if [ "$ak1_last_rotated" != "N/A" ] && [ "$ak1_last_rotated" != "no_information" ] && [[ "$ak1_last_rotated" < "$CUTOFF_ROTATION" ]]; then
                ak1_rotated=true
            fi
        fi
        
        if [ "$ak2_active" = "true" ]; then
            if [ "$ak2_last_rotated" != "N/A" ] && [ "$ak2_last_rotated" != "no_information" ] && [[ "$ak2_last_rotated" < "$CUTOFF_ROTATION" ]]; then
                ak2_rotated=true
            fi
        fi
        
        if [ "$cert1_active" = "true" ]; then
            if [ "$cert1_last_rotated" != "N/A" ] && [ "$cert1_last_rotated" != "no_information" ] && [[ "$cert1_last_rotated" < "$CUTOFF_ROTATION" ]]; then
                cert1_rotated=true
            fi
        fi
        
        if [ "$cert2_active" = "true" ]; then
            if [ "$cert2_last_rotated" != "N/A" ] && [ "$cert2_last_rotated" != "no_information" ] && [[ "$cert2_last_rotated" < "$CUTOFF_ROTATION" ]]; then
                cert2_rotated=true
            fi
        fi
        
        if [ "$pwd_rotated" = true ] || [ "$ak1_rotated" = true ] || [ "$ak2_rotated" = true ] || [ "$cert1_rotated" = true ] || [ "$cert2_rotated" = true ]; then
            pwd_display="${pwd_last_changed:-N/A}"
            ak1_rot_display="${ak1_last_rotated:-N/A}"
            ak2_rot_display="${ak2_last_rotated:-N/A}"
            cert1_display="${cert1_last_rotated:-N/A}"
            cert2_display="${cert2_last_rotated:-N/A}"
            
            echo -e "${arn}\t${pwd_display}\t${ak1_rot_display}\t${ak2_rot_display}\t${cert1_display}\t${cert2_display}" >> "$TEMP_ROTATION"
        fi
        
        # ANÁLISIS MFA
        if [ "$pwd_enabled" = "true" ]; then
            echo -e "${arn}\t${mfa_active}" >> "$TEMP_MFA"
        fi
    done
    
    echo ""
    
done < "$ACCOUNTS_FILE"

echo ""
echo "=== ANÁLISIS DE INACTIVIDAD (>${DAYS_INACTIVE} días) ==="
echo ""

if [ -s "$TEMP_INACTIVITY" ]; then
    (echo -e "ARN\tCONSOLE_LAST_USED\tACCESS_KEY_1_LAST_USED\tACCESS_KEY_2_LAST_USED";
    cat "$TEMP_INACTIVITY") | column -t -s $'\t'
else
    echo "No se encontraron identidades inactivas"
fi

echo ""
echo "=== ANÁLISIS DE ROTACIÓN DE CREDENCIALES (>${DAYS_ROTATION} días sin rotar) ==="
echo ""

if [ -s "$TEMP_ROTATION" ]; then
    (echo -e "ARN\tPASSWORD_LAST_CHANGED\tACCESS_KEY_1_LAST_ROTATED\tACCESS_KEY_2_LAST_ROTATED\tCERT_1_LAST_ROTATED\tCERT_2_LAST_ROTATED";
    cat "$TEMP_ROTATION") | column -t -s $'\t'
else
    echo "No se encontraron credenciales sin rotar"
fi

echo ""
echo "=== ANÁLISIS MFA (Acceso por consola) ==="
echo ""

if [ -s "$TEMP_MFA" ]; then
    (echo -e "ARN\tMFA_ACTIVE";
    cat "$TEMP_MFA") | column -t -s $'\t'
else
    echo "No se encontraron usuarios con acceso por consola"
fi

rm -f "$TEMP_INACTIVITY" "$TEMP_ROTATION" "$TEMP_MFA"

echo ""
echo "=== Auditoría completada ==="
echo "Reportes guardados en: $OUTPUT_DIR"
