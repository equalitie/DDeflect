Feature: User agent accesses DDeflect

Scenario: Get web site address
 Given site looked up
 Then it should resolve
 And the addresses should be deflect

Scenario: Get web index
 Given I have the IP address of a trusted edge
 When I request the index page
 It should contain unbundler code
 And a link to bundled content 
 And the bundled content link should be to a v-edge 

@Pending
Scenario: Get web assets
 Given I have a link to bundled content on a v-edge
 I should receive a valid encrypted bundle
 And I should be able to expand the encrypted bundle
 And it should contain files matching those in assets/test-site/

@Pending
Scenario: Bad v-edge
 Given I have a link to bundled content on a v-edge
 If I receive an invalid encrypted package
 Then I should tell the controller
 And the controller should return with a link to bundled content on a different v-edge

@Pending
Scenario: v-edge times out
 Given I have a link to bundled content on a v-edge
 If a request for that content takes longer than 20 seconds
 Then I should cancel the request
 And I should tell the controller
 And the controller should return with a link to bundled content on a different v-edge

@Pending
Scenario: handle POST request
Given I generate a POST request against a form
Then I should receive the contents from the proxy

@Pending
Scenario: Verify the Javascript and key are sent over https


