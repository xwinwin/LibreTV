//
document.addEventListener('DOMContentLoaded', function() {

    if (typeof SITE_CONFIG !== 'undefined') {
        if (SITE_CONFIG.name) {
            document.title = '关于我们 - ' + SITE_CONFIG.name;

            var siteLogo = document.getElementById('siteLogo');
            if (siteLogo) {
                siteLogo.textContent = SITE_CONFIG.name;
            }

            var siteAboutName = document.getElementById('siteAboutName');
            if (siteAboutName) {
                siteAboutName.textContent = '关于 ' + SITE_CONFIG.name;
            }

            var siteLogoAlt = document.getElementById('siteLogoAlt');
            if (siteLogoAlt) {
                siteLogoAlt.alt = SITE_CONFIG.name + ' Logo';
                if (SITE_CONFIG.logo) {
                    siteLogoAlt.src = SITE_CONFIG.logo;
                }
            }

            var siteAboutText = document.getElementById('siteAboutText');
            if (siteAboutText) {
                siteAboutText.textContent = SITE_CONFIG.name;
            }

            var sitePrivacy = document.getElementById('sitePrivacy');
            if (sitePrivacy) {
                sitePrivacy.textContent = SITE_CONFIG.name;
            }

            var siteDisclaimer = document.getElementById('siteDisclaimer');
            if (siteDisclaimer) {
                siteDisclaimer.textContent = SITE_CONFIG.name;
            }

            var siteFooter = document.getElementById('siteFooter');
            if (siteFooter) {
                siteFooter.textContent = SITE_CONFIG.name;
            }

            if (SITE_CONFIG.slogan) {
                var siteSlogan = document.getElementById('siteSlogan');
                if (siteSlogan) {
                    siteSlogan.textContent = SITE_CONFIG.name + ' - ' + SITE_CONFIG.slogan;
                }
            }
        }

        if (SITE_CONFIG.repository) {
            var sourceRepoUrl = document.getElementById('sourceRepoUrl');
            if (sourceRepoUrl) {
                sourceRepoUrl.href = SITE_CONFIG.repository;
            }
        }

        if (SITE_CONFIG.email) {
            var siteContact = document.getElementById('siteContact');
            if (siteContact) {
                siteContact.href = 'mailto:' + SITE_CONFIG.email;
                siteContact.textContent = SITE_CONFIG.email;
            }
        }
    }
});