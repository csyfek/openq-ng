# TortoiseHg 简单使用方法 #
## 什么是 Mercurial ？什么是 TortoiseHg ？ ##
Mercurial 是一种轻量级分布式版本控制系统，采用 Python 语言实现，易于学习和使用，扩展性强。其是基于 GNU General Public License (GPL) 授权的开源项目。
<br>
TortoiseHg 是一个跨平台的 Mercurial 分布式版本控制系统的可视化客户端工具。<br>
<br>
这里我们先讲讲 TortoiseHg 的使用，至于 Mercurial 的命令行使用，请自行 Google 之。<br>
<br>
<h2>安装 TortoiseHg</h2>
<ul><li>Linux：不同的发行版可以用各自的软件包管理器安装，或者从源代码编译。具体参见：<a href='http://tortoisehg.bitbucket.org/'>http://tortoisehg.bitbucket.org/</a>
</li><li>Windows：直接下载安装包安装。参见：<a href='http://bitbucket.org/tortoisehg/stable/downloads/'>http://bitbucket.org/tortoisehg/stable/downloads/</a>
<h2>TortoiseHg 的实质</h2>
TortoiseHg 的实质是通过hgtk命令附加不同的参数来调用 hg 命令并把结果以图形界面的方式显示出来。而 TortoiseHg 在 Windows 平台上的右键菜单是一种称为 overlay 的插件，从而方便地嵌入到 explorer 等组件以直观的显示仓库的情况。同样地，在 Gnome/Nautilus 里面也可以像 Windows 的 explorer 里面调出右键菜单，然后调用 TortoiseHg 。<br>
下面以 Windows 为例配合截图的方式来学习。</li></ul>

<h2>克隆(clone)一个仓库</h2>
建立仓库是非常频繁的操作，克隆(clone)更是从网上获取开发者代码最经常做的一件事。比如 openq-ng 里面的“Source”界面：<br>
<pre><code>Get a local copy of the openq-ng repository with this command:<br>
hg clone https://openq-ng.googlecode.com/hg/ openq-ng <br>
</code></pre>
我们只需要在 explorer 里面选中一个目录，如图的“CODE_TEST”目录，然后从展开的右键菜单中选择“克隆”选项：<br>
<img src='http://openq-ng.googlecode.com/files/clone1.png' />
<br>
<br>
然后填入我们的源路径和目标路径，如图：<br>
<a href='http://openq-ng.googlecode.com/files/clone2-new.PNG'>http://openq-ng.googlecode.com/files/clone2-new.PNG</a>
<br>
<br>
等待 TortoiseHg 从网上拉回仓库，完成后就得到我们的项目代码仓库了。<br>
<br>
<img src='http://openq-ng.googlecode.com/files/clone3.png' />
<br>