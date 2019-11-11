+-----------------------------------------------------------------------+
|                                    					|
|   	 Instructions d'installation d'AD via scripts PowerShell      	|
|                                    					|
|                                    					|
|Projet Annuaire et Supervision                     			|
|Grp : Joël Didier, Louis Marjolet, Charles Agostini, Vicente Vaz    	|
+-----------------------------------------------------------------------+

Pour configurer l'Active Directory principal, importer le script suivant sur le serveur S-GRP-AD01
puis lancer le en tant qu'administrateur:

ScriptInstall_S-GRP-AD01.ps1

-----------------------------------------------------------------------------------------
Pour lier le serveur Samba, importer le script suivant sur le serveur S-GRP-AD01 puis lancer le en tant qu'administrateur:

Insert-DataOnSambaAD.ps1

-----------------------------------------------------------------------------------------
Pour le serveur REPLICA de l'Active Directory principal, importer le script suivant sur le serveur S-GRP-AD02
puis lancer le en tant qu'administrateur:

ScriptInstall_S-GRP-AD02.ps1