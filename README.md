# namecheap-acme-hook

Un hook de Certbot DNS-01 para la API de Namecheap, diseñado en Python 3.10+ y sin dependencias externas complejas. Es compatible con Certbot 5.x y futuras versiones, ofreciendo una solución robusta, autónoma y fácil de mantener para la emisión y renovación automática de certificados SSL (incluyendo comodines/wildcards y múltiples dominios).

---

## Características

- ✔ **Compatibilidad Garantizada**: Compatible con Certbot 5.x y superiores mediante los hooks oficiales `--manual-auth-hook` y `--manual-cleanup-hook`.
- ✔ **Soporte Completo para Wildcards**: Emisión de certificados comodín (`*.dominio.com`) y multidominio en una sola ejecución.
- ✔ **Cero Dependencias Complejas**: No depende de `lexicon`, `certbot-dns-namecheap`, `acme` interno, ni librerías de terceros; solo requiere Python 3.10+ y `requests`.
- ✔ **Detección Inteligente del Dominio**: Algoritmo de resolución descendente para identificar automáticamente la raíz del dominio registrado (`SLD` y `TLD`) incluso en extensiones complejas (ej. `sub.example.co.uk`).
- ✔ **Detección Automática de IP**: Si no se define una IP en la configuración, detecta automáticamente la IP pública del servidor necesaria para autenticar contra la API de Namecheap.
- ✔ **Cliente DNS UDP Integrado**: Realiza validaciones directas de propagación TXT contra múltiples resolvedores (`1.1.1.1`, `8.8.8.8`, `9.9.9.9` y resolvedor del sistema) antes de finalizar el hook para asegurar el éxito ante Let's Encrypt.
- ✔ **Preservación de Registros**: Operación segura y no destructiva; lee los hosts DNS actuales y solo edita/elimina el registro `_acme-challenge` específico del token en curso sin alterar otros registros (`A`, `MX`, `CNAME`, SPF, etc.).
- ✔ **Logging Detallado**: Salidas claras con tiempos de ejecución, estados de propagación y manejo robusto de errores con reintentos automáticos.

---

## Estructura del Proyecto

```text
namecheap-acme-hook/
├── README.md               # Documentación en español
├── LICENSE                 # Licencia MIT
├── requirements.txt        # Dependencias (requests)
├── install.sh              # Script instalador automatizado
├── .gitignore              # Archivos ignorados por git
├── namecheap.ini.example   # Plantilla de configuración
└── namecheap_hook.py       # Hook monolítico ejecutable
```

---

## Requisitos Previos

1. **Python 3.10+** instalado en el sistema.
2. **Acceso a la API de Namecheap**:
   - Inicie sesión en Namecheap.
   - Vaya a **Profile -> Tools -> Namecheap API Access** y actívela.
   - Genere una **API Key**.
   - **IMPORTANTE**: Registre la dirección IP pública del servidor que ejecuta Certbot en la sección de IPs permitidas (White-listed IPs) en ese mismo panel.

---

## Instalación

Clone o descargue el repositorio y ejecute el script de instalación automática como root:

```bash
git clone https://github.com/Komarcalabs/namecheap-acme-hook.git
cd namecheap-acme-hook
sudo ./install.sh
```

El script realizará las siguientes operaciones:
1. Creará el directorio de instalación en `/opt/namecheap`.
2. Copiará `namecheap_hook.py` y le otorgará permisos de ejecución.
3. Copiará el archivo de configuración base a `/opt/namecheap/namecheap.ini`.
4. Instalará la dependencia `requests` usando el gestor de paquetes de Python del sistema.

---

## Configuración

Edite el archivo de configuración `/opt/namecheap/namecheap.ini` y añada sus credenciales:

```ini
[namecheap]
# Nombre de usuario de acceso a su cuenta Namecheap
user_name = tu_usuario

# Usuario de API (normalmente el mismo que user_name)
api_user = tu_usuario

# API Key generada desde el panel de control de Namecheap
api_key = tu_api_key

# IP pública del servidor ejecutando Certbot.
# Si se deja vacío, el hook intentará auto-detectar su IP pública de forma automática.
client_ip =

# TTL para el registro TXT _acme-challenge (por defecto: 60)
ttl = 60

# Tiempo máximo (segundos) de espera para la propagación DNS (por defecto: 300)
propagation_timeout = 300

# Intervalo de consulta (segundos) para verificar propagación (por defecto: 15)
propagation_interval = 15

# Usar el sandbox de desarrollo de Namecheap para pruebas (por defecto: false)
sandbox = false
```

---

## Ejemplos de Uso con Certbot

### 1. Certificado Comodín (Wildcard)

Para emitir un certificado para un dominio principal y todos sus subdominios (`*.dominio.com`):

```bash
certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "/opt/namecheap/namecheap_hook.py auth" \
  --manual-cleanup-hook "/opt/namecheap/namecheap_hook.py cleanup" \
  -d "dominio.com" \
  -d "*.dominio.com"
```

### 2. Certificado Multidominio (SAN)

Para proteger múltiples dominios independientes en un único certificado SSL:

```bash
certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "/opt/namecheap/namecheap_hook.py auth" \
  --manual-cleanup-hook "/opt/namecheap/namecheap_hook.py cleanup" \
  -d "dominio1.com" \
  -d "www.dominio1.com" \
  -d "dominio2.net" \
  -d "app.dominio2.net"
```

### 3. Renovación Automática

Certbot almacena los parámetros de los hooks utilizados en la primera emisión. Por lo tanto, para renovar todos sus certificados SSL emitidos por este hook de forma automática, basta con programar una tarea cron o systemd timer que ejecute el siguiente comando:

```bash
certbot renew
```

Para probar que la renovación automática funciona correctamente sin emitir un certificado real, ejecute:

```bash
certbot renew --dry-run
```

---

## Ejemplo de Logs de Ejecución

### Durante la Autenticación (`auth`):
```text
[INFO] Starting DNS-01 authentication challenge for domain: dominio.com
[INFO] Detected registered domain: dominio.com (Subdomain prefix: '')
[INFO] Adding TXT record: _acme-challenge.dominio.com -> 'ab12cd34ef56gh78ij90kl_mn' (TTL: 60)
[INFO] Checking for DNS propagation of TXT record at '_acme-challenge.dominio.com'...
[INFO] Waiting for propagation... (Elapsed: 0s / Timeout: 300s)
[INFO] Waiting for propagation... (Elapsed: 15s / Timeout: 300s)
[INFO] Success! TXT validation value found on resolver 1.1.1.1 (15s elapsed).
[INFO] DNS-01 auth challenge successfully completed in 17.43s total.
```

### Durante la Limpieza (`cleanup`):
```text
[INFO] Starting DNS-01 cleanup challenge for domain: dominio.com
[INFO] Detected registered domain: dominio.com (Subdomain prefix: '')
[INFO] Removing 1 matching TXT records for _acme-challenge.dominio.com.
[INFO] DNS-01 cleanup challenge successfully completed in 2.10s total.
```

---

## Troubleshooting (Resolución de Problemas)

### 1. Error `API Key is invalid or API access has not been enabled`
- **Causa**: La API Key en `namecheap.ini` es incorrecta o no ha activado el acceso a la API en su perfil de Namecheap.
- **Solución**: Verifique sus credenciales. Recuerde que el entorno de producción y el sandbox usan API Keys diferentes.

### 2. Error `Error 2019166: Domain is not associated with your account`
- **Causa**: El dominio especificado en Certbot no se encuentra registrado bajo la cuenta de Namecheap configurada.
- **Solución**: Asegúrese de que el dominio está activo en la misma cuenta de la API Key.

### 3. Error `Error 2030288: Cannot complete this command as this domain is not using proper DNS servers`
- **Causa**: El dominio utiliza servidores DNS de terceros (ej. Cloudflare, Route53) en lugar de los nombreservidores predeterminados de Namecheap (`PremiumDNS` o `BasicDNS`).
- **Solución**: Este hook requiere que use los servidores DNS predeterminados de Namecheap. Si utiliza otra plataforma, debe buscar un hook específico para ese proveedor de DNS.

### 4. Requisitos de IP (Whitelisting)
Si recibe errores relacionados con conexiones rechazadas o IPs no permitidas, compruebe que la IP del servidor aparece en la lista blanca de la API en el panel de Namecheap. Si el servidor tiene IP dinámica, deje la directiva `client_ip` vacía en `/opt/namecheap/namecheap.ini` para que el hook autodetecte la IP pública dinámicamente y pueda verificarla con el soporte técnico o actualizar la lista blanca.

---

## Licencia

Este proyecto está bajo la Licencia MIT. Consulte el archivo [LICENSE](LICENSE) para más detalles.
