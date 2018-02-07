def mon_decorateur(fonction):
    print("Notre décorateur est appelé avec en paramètre la fonction {0}".format(fonction))
    return fonction

@mon_decorateur
def salut():
    print("Salut !")

salut()
