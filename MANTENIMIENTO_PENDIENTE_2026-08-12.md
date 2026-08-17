# Mantenimiento del repositorio — actualizado 2026-08-17

## Publicación y automatización

- Origen canónico: `https://github.com/LynxPardelle/zoolanding-notifications`.
- Ramas base publicadas: `main`, `test` y `dev`; promoción `dev -> test -> main`.
- CI tiene permisos de lectura. Los Environments limitan `test` a la rama `test`
  y `production` a `main`.
- Roles OIDC/CloudFormation y topic de alarmas están configurados como secretos
  de cada GitHub Environment, sin claves AWS estáticas. Las variables antiguas
  deben eliminarse sólo después de verificar este workflow en GitHub.
- La CI incluye Gitleaks fijado por SHA, historial completo, cancelación de runs
  obsoletos y límites de tiempo. Los identificadores AWS sólo llegan a los pasos
  que los consumen y el ID de cuenta se enmascara.
- El adaptador SMTP reintenta fallos de red anteriores a `DATA`, mantiene como
  ambiguos los fallos durante el envío y falla cerrado ante certificados inválidos.
- Validación local: 67/67 pruebas pasaron tres veces, compilación, SAM lint,
  Actionlint y Gitleaks de historial correctos; no se envió ningún mensaje real.
  `sam build` local sigue bloqueado por el wrapper `pip`/OpenSSL de esta instalación
  Windows; la CI Linux debe producir y verificar el artefacto antes de promoverlo.

## Despliegue pendiente

**NO-GO para desplegar la aplicación.** Sólo existen las identidades retenidas.
Faltan el stack Notifications, parámetros SSM, secretos por borrador, cuenta y
dominio SMTP2GO auditados, cuotas, pruebas de fallos y evidencia de entrega. El
topic de alarmas tiene cero suscriptores confirmados.

También faltan un lock transitivo con hashes, aprobación independiente en ramas
y Environments, y una prueba automática de suscriptor confirmado/canario de
alarmas. Mantenga despliegues deshabilitados hasta cerrar estos puntos. Use pull
requests, CI y pushes normales; nunca fuerce historia.

No transfiera destinatarios, cuerpos, credenciales SMTP, respuestas de
proveedor, logs, `.aws-sam`, cachés ni entornos virtuales. Clone GitHub y obtenga
valores reales sólo del gestor de secretos autorizado.
