---
name: New Issue Template
about: Template for new issues to ensure consistent style.
title: Make xyzzy do frotz
labels: ''
assignees: ''

---

# Feature Branch

Current feature branch for this issue: [not created yet](../tree/feature/issue-12345/projectname-branchversion).

## Progress

- [ ] Create a task list for this issue.
  1. If you have no idea what needs to be done to fix an issue, use a boilerplate task.
  2. Compared to deleting this entire section, a boilerplate task will list its progress as 0/1 or 0%.
  3. The task list is designed to be edited.
- [ ] Proposed task needed to fix this issue
  - [ ] Something that will aid in doing that
- [ ] Another task to do
- [ ] Some thoughts on how to approach the issue
  - [ ] An alternative route to take
    * Why this might not be the better route.
- [ ] Mark tasks as completed
  - [x] Commit 123def7 added:
    * first thing (if it only added one thing, no need for a list here)
    * second thing
      * Don't mention issue numbers in commit messages unless directly working on the master branch.
        * The master branch has linear history. 
        * Mentioning an issue in a commit message, other than **Closes #12345** at the end of a multi-line commit message, will add a reference to that commit to the bottom of the issue's page.
        * Every single time the hash of that commit changes, whether through rebasing, cherry-picking, or the like, a mention of the new commit hash will also be added to the bottom of the issue's page.
        * That can result in the same commit being listed dozens of times for an issue, a separate mention for each hash.
        * Thus, it is cleaner to reference commits in the task list. If a new feature branch changes commit hashes, there is only one place needed to change the commit references.
          * If that feature branch version is a dead end and a new version is created from a previous version, the original post revision history will have the previously referenced commit hashes.
  - [ ] Delete tasks that are no longer relevant.
    * Only task lists in the original post for an issue get counted in issue tracking progress.
    * Move and rename tasks as need be while making progress.
      * Previous revisions of the original post of an issue (as well as revisions of comments) can be reviewed by clicking on *Edited*.

### Repository Project ProjectName

- [ ] Proposed task needed to fix this issue
  * Complex issues may involve multiple Repository Projects. Multiple task lists may make sense.

### Repository Project OtherProjectName

- [ ] Another proposed task needed to fix this issue
  * Complex issues may involve multiple Repository Projects. Multiple task lists may make sense.
  - [x] Commit abc4567 did something really cool.
    * Use the past tense when saying what a commit does.
    * This is different to the tense used in commit messages, where the git style is used:
      > Describe your changes in imperative mood, e.g. "make xyzzy do frotz"
instead of "[This patch] makes xyzzy do frotz" or "[I] changed xyzzy
to do frotz", as if you are giving orders to the codebase to change
its behavior.  Try to make sure your explanation can be understood
without external resources. Instead of giving a URL to a mailing list
archive, summarize the relevant points of the discussion.
&mdash;imperative-mood, Describe your changes well, [Submitting Patches](https://git.kernel.org/pub/scm/git/git.git/plain/Documentation/SubmittingPatches?id=HEAD), Git Documentation

---

# Background

This is where any additional information can go.

There is, essentially, no limit on how much text can go here.

For anything not directly related to the cause of the issue, such as research on how to resolve the problem, it is probably better to do so in a comment rather than in the original post.

Why better? Scrolling when editing the original post. If you're in preview mode, the entire post is visible and the save changes button is way down at the bottom. While you could go back to edit mode, you're more likely editing the OP to edit the task list which is at the top of the post.

As for the title of an issue, where appropriate it should eventually be in the *imperative mood* present tense. An issue is, unless labelled **wontfix**, an order to the codebase to change its behaviour. By using the same tense in an issue as used in commit messages, for simple issues the commit message could be exactly the same as the issue title.