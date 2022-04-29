# YARA

rule KB4_SECURITY : KB4_SECURITY
{
    meta:
        author = "WCOREION"
        description = "The top subject lines according to Barracuda analysis to indicate security issues in phishing attempts"
        date = "2022-2-7"
    strings:
        $ = /(\n|\r)From:.{0,200}follow.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}follow/ nocase

        $ = /(\n|\r)From:.{0,200}update.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}updat/ nocase

        $ = /(\n|\r)From:.{0,200}request.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}request/ nocase

        $ = /(\n|\r)From:.{0,200}password.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}password/ nocase

        $ = /(\n|\r)From:.{0,200}encrypt.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}encrypt/ nocase

        $ = /(\n|\r)From:.{0,200}account.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}account/ nocase

        $ = /(\n|\r)From:.{0,200}terminated.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}terminated/ nocase

				$ = /(\n|\r)From:.{0,200}urgent.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}urgent/ nocase
        
        $ = /(\n|\r)From:.{0,200}payment.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}payment/ nocase
        
        $ = /(\n|\r)From:.{0,200}invoice.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}invoice/ nocase
        
        $ = /(\n|\r)From:.{0,200}re:.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}re:/ nocase
        
        $ = /(\n|\r)From:.{0,200}deposit.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}deposit/ nocase
        
        $ = /(\n|\r)From:.{0,200}payroll.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}payroll/ nocase
        
        $ = /(\n|\r)From:.{0,200}expenses.{0,200}/ nocase
        $ = /(\n|\r)Subject:.{0,200}expenses/ nocase



        
    condition:
		any of them
}
