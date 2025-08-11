
// ! Bu araç @keyiflerolsun tarafından | @KekikAkademi için yazılmıştır.

package com.keyiflerolsun

import com.lagradost.api.Log
import com.lagradost.cloudstream3.*
import com.lagradost.cloudstream3.utils.*
import com.fasterxml.jackson.annotation.JsonProperty

open class DzenRu : ExtractorApi() {
    override val name            = "DzenRu"
    override val mainUrl         = "https://dzen.ru"
    override val requiresReferer = true

    override suspend fun getUrl(url: String, referer: String?, subtitleCallback: (SubtitleFile) -> Unit, callback: (ExtractorLink) -> Unit) {
        val videoKey = url.split("/").last()
        val videoUrl = "${mainUrl}/embed/${videoKey}"
        Log.d("Kekik_${this.name}", "videoUrl: $videoUrl")

        val html = app.get(videoUrl).text

        val regex = Regex("""https://vd\d+\.okcdn\.ru/\?[^"'\\\s]+""")
        val matches = regex.findAll(html).map { it.value }.toList()

        if (matches.isEmpty()) throw ErrorLoadingException("DzenRu video link not found.")

        for (link in matches.distinct()) {
            callback.invoke(
                newExtractorLink(
                    source  = this.name,
                    name    = this.name,
                    url     = link,
                    type    = ExtractorLinkType.DASH,
                ) {
                    headers = mapOf("Referer" to mainUrl)
                    this.quality = Qualities.Unknown.value
                }
            )
        }
    }

    data class DzenRuUrls(
        @JsonProperty("urls") val urls: List<DzenRuData>
    )

    data class DzenRuData(
        @JsonProperty("url")   val url: String,
        @JsonProperty("label") val label: String,
    )
}
