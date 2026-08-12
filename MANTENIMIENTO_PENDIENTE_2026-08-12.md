# Mantenimiento pendiente — 2026-08-12

## Publicación bloqueada de forma segura

Este repositorio no tiene remoto configurado. Su historial se conservó sin
crear un destino GitHub ni inferir visibilidad.

- Destino candidato, sujeto a aprobación: `LynxPardelle/zoolanding-notifications`.
- Visibilidad recomendada hasta revisar el rollout de correo: **privada**.
- Rama actual: `codex/phase8-infrastructure-readiness`.
- Validación local: 65/65 pruebas, compilación Python y
  `sam validate --lint` correctos.
- Despliegue/envío: **NO-GO**; no se creó infraestructura, no se leyó un secreto
  y no se envió ningún mensaje.

Cuando se apruebe un repositorio, agregue el `origin` exacto y publique primero
esta rama con un push normal. Preserve `dev -> test -> main`, no fuerce historia
y mantenga las ramas de fases anteriores hasta verificar su alcance remoto.

Al transferir, excluya direcciones, cuerpos o variables de mensajes,
credenciales SMTP, respuestas de proveedor, secretos de destinatarios,
artefactos SAM y entornos virtuales. Los valores reales deben viajar sólo por
el gestor de secretos y el procedimiento operativo aprobados.
