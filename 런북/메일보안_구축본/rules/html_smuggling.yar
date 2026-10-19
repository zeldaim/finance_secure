/*
  html_smuggling.yar - HTML smuggling 첨부 탐지 (랩/교육용)
  사용: yara html_smuggling.yar <첨부파일>    (yara 설치 필요)
  설계: Blob 생성 + Base64 디코딩 + 강제 다운로드 저장 조합을 탐지.
  주의: 정상 웹앱도 Blob을 쓸 수 있어 2개 이상 동시 충족을 조건으로 오탐을 줄임.
*/

rule HTML_Smuggling_Lab
{
    meta:
        description = "HTML smuggling: atob + Blob + forced save"
        author      = "fin-sec-lab"
        reference   = "MITRE ATT&CK T1027.006, T1566"
        severity    = "high"
    strings:
        $save1 = "msSaveOrOpenBlob" nocase
        $save2 = ".click()" nocase
        $blob  = "new Blob" nocase
        $octet = "application/octet-stream" nocase
        $b64   = /atob\(["'][A-Za-z0-9+\/=]{120,}/
        $href  = /href\s*=\s*["']data:application\/octet-stream;base64,/ nocase
    condition:
        filesize < 2MB and
        (
          ($blob and $b64 and (any of ($save1, $save2, $octet))) or
          ($href and $b64)
        )
}

rule EICAR_Test_File
{
    meta:
        description = "EICAR 표준 안티바이러스 테스트 파일(악성 모사)"
        severity    = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
