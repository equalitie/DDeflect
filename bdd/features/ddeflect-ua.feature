Feature: DDeflect UA

Scenario: Get web site address

    When I request activist.org from DNS
    then I should receive an IP address
    and it should be a trusted edge

Scenario: Get web index

    When I request http://activist.org
    then it should contain unbundler code
    and a link to bundled content on a v-edge

Scenario: Get web assets

    When I request the link to bundled content from good v-edge
    then I should receive a valid encrypted bundle
    and it should contain valid web content

Scenario: Bad v-edge

    When I request the link to bundled content from bad v-edge
    then I should receive a invalid encrypted bundle
    then I should notify the trusted edge
    and I should receive a report response
    and a link to bundled content on a v-edge

Scenario: v-edge times out

    When I request the link to bundled content from offline v-edge
    and it takes longer than 5 seconds
    then I should notify the trusted edge
    and I should receive a report response
    then it should contain unbundler code
    and a link to bundled content on a v-edge
