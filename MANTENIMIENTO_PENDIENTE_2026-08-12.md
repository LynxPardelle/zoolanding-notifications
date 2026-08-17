# Mantenimiento del repositorio — actualizado 2026-08-17

## Publicación y automatización

- Origen canónico privado: `https://github.com/LynxPardelle/zoolanding-notifications`.
- Ramas base publicadas: `main`, `test` y `dev`; promoción `dev -> test -> main`.
- CI tiene permisos de lectura. Los Environments limitan `test` a la rama `test`
  y `production` a `main`.
- Roles OIDC/CloudFormation y topic de alarmas están configurados sin claves AWS
  estáticas.
- Validación local: 65/65 pruebas, compilación, SAM, Actionlint y Gitleaks; no se
  envió ningún mensaje real.

## Despliegue pendiente

**NO-GO para desplegar la aplicación.** Sólo existen las identidades retenidas.
Faltan el stack Notifications, parámetros SSM, secretos por borrador, cuenta y
dominio SMTP2GO auditados, cuotas, pruebas de fallos y evidencia de entrega. El
topic de alarmas tiene cero suscriptores confirmados.

La protección de ramas privadas fue rechazada por el plan GitHub actual. Se
mantuvo la visibilidad privada; use pull requests, CI y pushes normales, y nunca
fuerce historia.

No transfiera destinatarios, cuerpos, credenciales SMTP, respuestas de
proveedor, logs, `.aws-sam`, cachés ni entornos virtuales. Clone GitHub y obtenga
valores reales sólo del gestor de secretos autorizado.
