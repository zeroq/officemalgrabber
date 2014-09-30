# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import os
import imp

class pluginLoader:
    def __init__(self, fileFormat, docType, fileName):
        pathToPluginFiles = './modules/CVE_detection' + fileFormat + docType
        self.pluginFiles = []
        self.loadedPlugins = []

        self.pluginFiles = os.listdir(pathToPluginFiles)


        for plugin in self.pluginFiles:
            if plugin.split('.')[-1] != 'py':
                self.pluginFiles.remove(plugin)

        for plugin in self.pluginFiles:
            imported = imp.load_source(plugin.split('.')[0], pathToPluginFiles + '/' + plugin)
            self.loadedPlugins += [imported.getNewInstance(fileName, docType)]

    def runDetectors(self):
        for plugin in self.loadedPlugins:
            plugin.check()
