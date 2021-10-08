# Contributing

Before we can accept a pull request from you, you'll need to sign a [Contributor License Agreement (CLA)](https://cla.microsoft.com). It is an automated process and you only need to do it once.
To enable us to quickly review and accept your pull requests, always create one pull request per issue and link the issue in the pull request. Never merge multiple requests in one unless they have the same root cause. Be sure to follow our Coding Guidelines and keep code changes as small as possible. Avoid pure formatting changes to code that has not been modified otherwise. Pull requests should contain tests whenever possible.

# Branching
The master branch contains current development.  While CI should ensure that master always builds, it is still considered pre-release code.  Release checkpoints will be put into stable branches for maintenance.

To contribute, fork the repository and create a branch in your fork for your work.  Please keep branch names short and descriptive.  Please direct PRs into the upstream master branch.

# Testing
* There are a multitude of tests included in the `tests` directory of the repository.  
* Add new tests corresponding to your change, if applicable. Include tests when adding new features. When fixing bugs, start with adding a test that highlights how the current behavior is broken.  
* Make sure that the tests are all passing, including your new tests.

# Pull Requests
* Always tag a work item or issue with a pull request.
* Limit pull requests to as few issues as possible, preferably 1 per PR


