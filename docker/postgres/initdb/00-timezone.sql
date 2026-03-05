ALTER SYSTEM SET timezone TO 'America/Sao_Paulo';
SELECT pg_reload_conf();
SHOW timezone;
